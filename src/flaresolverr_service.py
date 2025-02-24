import logging
import platform
import random
import sys
import time
from datetime import timedelta
from html import escape
from urllib.parse import unquote, quote

from func_timeout import FunctionTimedOut, func_timeout
from selenium.common import TimeoutException
from selenium.webdriver.chrome.webdriver import WebDriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import (
    presence_of_element_located, staleness_of, title_is)
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.wait import WebDriverWait

import utils
from dtos import (STATUS_ERROR, STATUS_OK, ChallengeResolutionResultT,
                  ChallengeResolutionT, HealthResponse, IndexResponse,
                  V1RequestBase, V1ResponseBase)
from sessions import SessionsStorage

ACCESS_DENIED_TITLES = [
    # Cloudflare
    'Access denied',
    # Cloudflare http://bitturk.net/ Firefox
    'Attention Required! | Cloudflare'
]
ACCESS_DENIED_SELECTORS = [
    # Cloudflare
    'div.cf-error-title span.cf-code-label span',
    # Cloudflare http://bitturk.net/ Firefox
    '#cf-error-details div.cf-error-overview h1'
]
CHALLENGE_TITLES = [
    # Cloudflare
    'Just a moment...',
    # DDoS-GUARD
    'DDoS-Guard'
]
CHALLENGE_SELECTORS = [
    # Cloudflare
    '#cf-challenge-running', '.ray_id', '.attack-box', '#cf-please-wait', '#challenge-spinner', '#trk_jschal_js',
    '#turnstile-wrapper', '.lds-ring',
    # Custom CloudFlare for EbookParadijs, Film-Paleis, MuziekFabriek and Puur-Hollands
    'td.info #js_info',
    # Fairlane / pararius.com
    'div.vc div.text-box h2'
]
SHORT_TIMEOUT = 1
LONG_TIMEOUT = 5
SESSIONS_STORAGE = SessionsStorage()


def test_browser_installation():
    logging.info("Testing web browser installation...")
    logging.info("Platform: " + platform.platform())

    chrome_exe_path = utils.get_chrome_exe_path()
    if chrome_exe_path is None:
        logging.error("Chrome / Chromium web browser not installed!")
        sys.exit(1)
    else:
        logging.info("Chrome / Chromium path: " + chrome_exe_path)

    chrome_major_version = utils.get_chrome_major_version()
    if chrome_major_version == '':
        logging.error("Chrome / Chromium version not detected!")
        sys.exit(1)
    else:
        logging.info("Chrome / Chromium major version: " + chrome_major_version)

    logging.info("Launching web browser...")
    user_agent = utils.get_user_agent()
    logging.info("FlareSolverr User-Agent: " + user_agent)
    logging.info("Test successful!")


def index_endpoint() -> IndexResponse:
    res = IndexResponse({})
    res.msg = "FlareSolverr is ready!"
    res.version = utils.get_flaresolverr_version()
    res.userAgent = utils.get_user_agent()
    return res


def health_endpoint() -> HealthResponse:
    res = HealthResponse({})
    res.status = STATUS_OK
    return res


def controller_v1_endpoint(req: V1RequestBase) -> V1ResponseBase:
    start_ts = int(time.time() * 1000)
    logging.info(f"Incoming request => POST /v1 body: {utils.object_to_dict(req)}")
    res: V1ResponseBase
    try:
        res = _controller_v1_handler(req)
    except Exception as e:
        res = V1ResponseBase({})
        res.__error_500__ = True
        res.status = STATUS_ERROR
        res.message = "Error: " + str(e)
        logging.error(res.message)

    res.startTimestamp = start_ts
    res.endTimestamp = int(time.time() * 1000)
    res.version = utils.get_flaresolverr_version()
    logging.debug(f"Response => POST /v1 body: {utils.object_to_dict(res)}")
    logging.info(f"Response in {(res.endTimestamp - res.startTimestamp) / 1000} s")
    return res


def _controller_v1_handler(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.cmd is None:
        raise Exception("Request parameter 'cmd' is mandatory.")
    if req.headers is not None:
        logging.warning("Request parameter 'headers' was removed in FlareSolverr v2.")
    if req.userAgent is not None:
        logging.warning("Request parameter 'userAgent' was removed in FlareSolverr v2.")

    # set default values
    if req.maxTimeout is None or int(req.maxTimeout) < 1:
        req.maxTimeout = 60000

    # execute the command
    res: V1ResponseBase
    if req.cmd == 'sessions.create':
        res = _cmd_sessions_create(req)
    elif req.cmd == 'sessions.list':
        res = _cmd_sessions_list(req)
    elif req.cmd == 'sessions.destroy':
        res = _cmd_sessions_destroy(req)
    elif req.cmd == 'request.get':
        res = _cmd_request_get(req)
    elif req.cmd == 'request.post':
        res = _cmd_request_post(req)
    else:
        raise Exception(f"Request parameter 'cmd' = '{req.cmd}' is invalid.")

    return res


def _cmd_request_get(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.url is None:
        raise Exception("Request parameter 'url' is mandatory in 'request.get' command.")
    if req.postData is not None:
        raise Exception("Cannot use 'postBody' when sending a GET request.")
    if req.returnRawHtml is not None:
        logging.warning("Request parameter 'returnRawHtml' was removed in FlareSolverr v2.")
    if req.download is not None:
        logging.warning("Request parameter 'download' was removed in FlareSolverr v2.")

    challenge_res = _resolve_challenge(req, 'GET')
    res = V1ResponseBase({})
    res.status = challenge_res.status
    res.message = challenge_res.message
    res.solution = challenge_res.result
    return res


def _cmd_request_post(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.postData is None:
        raise Exception("Request parameter 'postData' is mandatory in 'request.post' command.")
    if req.returnRawHtml is not None:
        logging.warning("Request parameter 'returnRawHtml' was removed in FlareSolverr v2.")
    if req.download is not None:
        logging.warning("Request parameter 'download' was removed in FlareSolverr v2.")

    challenge_res = _resolve_challenge(req, 'POST')
    res = V1ResponseBase({})
    res.status = challenge_res.status
    res.message = challenge_res.message
    res.solution = challenge_res.result
    return res


def _cmd_sessions_create(req: V1RequestBase) -> V1ResponseBase:
    logging.debug("Creating new session...")

    session, fresh = SESSIONS_STORAGE.create(session_id=req.session, proxy=req.proxy)
    session_id = session.session_id

    if not fresh:
        return V1ResponseBase({
            "status": STATUS_OK,
            "message": "Session already exists.",
            "session": session_id
        })

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "Session created successfully.",
        "session": session_id
    })


def _cmd_sessions_list(req: V1RequestBase) -> V1ResponseBase:
    session_ids = SESSIONS_STORAGE.session_ids()

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "",
        "sessions": session_ids
    })


def _cmd_sessions_destroy(req: V1RequestBase) -> V1ResponseBase:
    session_id = req.session
    existed = SESSIONS_STORAGE.destroy(session_id)

    if not existed:
        raise Exception("The session doesn't exist.")

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "The session has been removed."
    })


def _init_driver(driver):
    try:
        driver.execute_cdp_cmd('Page.enable', {})
        driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
            'source': """
                Element.prototype._as = Element.prototype.attachShadow;
                Element.prototype.attachShadow = function (params) {
                    return this._as({mode: "open"})
                };
            """
        })
    except Exception as e:
        logging.debug("Driver init exception: %s", repr(e))


def _resolve_challenge(req: V1RequestBase, method: str) -> ChallengeResolutionT:
    timeout = int(req.maxTimeout) / 1000
    driver = None
    try:
        if req.session:
            session_id = req.session
            ttl = timedelta(minutes=req.session_ttl_minutes) if req.session_ttl_minutes else None
            session, fresh = SESSIONS_STORAGE.get(session_id, ttl)

            if fresh:
                logging.debug(f"new session created to perform the request (session_id={session_id})")
            else:
                logging.debug(f"existing session is used to perform the request (session_id={session_id}, "
                              f"lifetime={str(session.lifetime())}, ttl={str(ttl)})")

            driver = session.driver
        else:
            driver = utils.get_webdriver(req.proxy)
            logging.debug('New instance of webdriver has been created to perform the request')
        _init_driver(driver)
        return func_timeout(timeout, _evil_logic, (req, driver, method))
    except FunctionTimedOut:
        raise Exception(f'Error solving the challenge. Timeout after {timeout} seconds.')
    except Exception as e:
        raise Exception('Error solving the challenge. ' + str(e).replace('\n', '\\n'))
    finally:
        if not req.session and driver is not None:
            if utils.PLATFORM_VERSION == "nt":
                driver.close()
            driver.quit()
            logging.debug('A used instance of webdriver has been destroyed')


def wait_for_element_by_css(driver, css_selector: str):
    try:
        element = WebDriverWait(driver, LONG_TIMEOUT).until(
            presence_of_element_located((By.CSS_SELECTOR, css_selector)))
        # element = driver.find_elements(By.CSS_SELECTOR, css_selector)  # Avoid expect to save time
        return element
    except:
        logging.debug(f"Element with css selector: {css_selector}, not found!")
        return None


def get_shadowed_iframe(driver: WebDriver, css_selector: str):
    logging.debug("Getting ShadowRoot by selector: %s", css_selector)
    shadow_element = driver.execute_script("""
        return document.querySelector(arguments[0]).shadowRoot.firstChild;
    """, css_selector)
    if shadow_element:
        logging.debug("iframe found")
    else:
        logging.debug("iframe not found")
    return shadow_element


def move_mouse_randomly(driver):
    actions = ActionChains(driver)

    def perform_random_move(_driver, _actions):
        # Get the size of the window
        window_width = _driver.execute_script("return window.innerWidth")
        window_height = _driver.execute_script("return window.innerHeight")

        # Generate random positions within the window dimensions
        random_x = random.randint(0, int(window_width / 4))
        random_y = random.randint(0, int(window_height / 4))

        # Move the mouse to the random position
        _actions.move_by_offset(random_x, random_y).double_click().pause(random.uniform(0, 2))

    # Simulate mouse moving randomly
    for _ in range(2):  # Move the mouse 5 times randomly
        perform_random_move(driver, actions)
    actions.click_and_hold().pause(1).release().perform()


def click_verify_direct(driver: WebDriver):
    try:
        logging.debug("Try to find the Cloudflare verify checkbox...")
        iframe = get_shadowed_iframe(driver, "div:not(:has(div))")
        driver.switch_to.frame(iframe)
        iframe_body = wait_for_element_by_css(driver, "body")
        if iframe_body:
            iframe_body.click()
            actions = ActionChains(driver)
            actions.move_to_element_with_offset(iframe_body, 10, 10)
            actions.context_click().pause(3).click()
            actions.perform()
            logging.debug("Attempted to click on iframe body")
    except Exception as e:
        logging.debug("Cloudflare verify checkbox not found on the page. %s", repr(e))
    finally:
        driver.switch_to.default_content()

    try:
        logging.debug("Try to find the Cloudflare 'Verify you are human' button...")
        button = wait_for_element_by_css(driver, "input[type=checkbox]")
        if button:
            actions = ActionChains(driver)
            actions.move_to_element_with_offset(button, 5, 7)
            actions.click(button)
            actions.perform()
            logging.debug("The Cloudflare 'Verify you are human' button found and clicked!")
    except Exception:
        logging.debug("The Cloudflare 'Verify you are human' button not found on the page.")

    time.sleep(2)


def click_verify_with_actions(driver: WebDriver):
    try:
        logging.debug("Try to check the Cloudflare verify checkbox...")

        # Find the pivot element (in this case, the header)
        if pivot_element := driver.find_elements(By.CSS_SELECTOR, "h1.zone-name-title.h1"):
            # Get the position of the pivot element
            location = pivot_element.location
            logging.debug(f"Pivot element location {location}")
            pivot_x = location['x']
            pivot_y = location['y']

            # We adjust the click offset based on the pivot element
            offset_x = -430
            offset_y = 130

            # Create ActionChains object
            actions = ActionChains(driver)

            # Move to the pivot element (simulates moving the mouse to the pivot element)
            actions.move_to_element(pivot_element).pause(1).double_click().pause(2)

            # Move the mouse by the calculated offset (relative to the pivot element)
            actions.move_to_element_with_offset(pivot_element, offset_x, offset_y).pause(2)

            # Perform the click
            actions.click().perform()

            logging.debug(f"Moved to position: ({pivot_x}, {pivot_y}) with offset: ({offset_x}, {offset_y})")

            time.sleep(15)

            logging.debug("Cloudflare verify checkbox click attempted!")
    except Exception:
        logging.debug("Cloudflare verify checkbox turnstile not found on the page.")

    time.sleep(2)


def get_correct_window(driver: WebDriver, url: str, close_other_tabs: bool = True) -> WebDriver:
    if len(driver.window_handles) > 1:
        window_to_keep = None
        for window_handle in reversed(driver.window_handles):
            current_url = driver.current_url
            if current_url.startswith(url) and not window_to_keep:
                window_to_keep = window_handle
            elif close_other_tabs:
                driver.switch_to.window(window_handle)
                driver.close()
        driver.switch_to.window(window_to_keep)
    return driver


def access_page(driver: WebDriver, url: str) -> None:
    driver.get(url)
    driver.start_session()
    driver.start_session()  # required to bypass Cloudflare


def switch_to_new_tab(driver: WebDriver, url: str):
    logging.debug("Opening new tab...")
    driver.execute_script(f"window.open('{url}', 'new tab')")
    driver.switch_to.window(driver.window_handles[-1])
    _init_driver(driver)
    time.sleep(1)
    driver.get(url)
    return driver


def _evil_logic(req: V1RequestBase, driver: WebDriver, method: str) -> ChallengeResolutionT:
    res = ChallengeResolutionT({})
    res.status = STATUS_OK
    res.message = ""

    # navigate to the page
    logging.debug(f'Navigating to... {req.url}')
    if method == 'POST':
        _post_request(req, driver)
    else:
        access_page(driver, req.url)
    driver = get_correct_window(driver, req.url)

    # set cookies if required
    if req.cookies is not None and len(req.cookies) > 0:
        logging.debug(f'Setting cookies...')
        for cookie in req.cookies:
            driver.delete_cookie(cookie['name'])
            driver.add_cookie(cookie)
        # reload the page
        if method == 'POST':
            _post_request(req, driver)
        else:
            access_page(driver, req.url)
        driver = get_correct_window(driver, req.url)

    # wait for the page
    if utils.get_config_log_html():
        logging.debug(f"Response HTML:\n{driver.page_source}")
    html_element = driver.find_element(By.TAG_NAME, "html")
    page_title = driver.title

    # find access denied titles
    for title in ACCESS_DENIED_TITLES:
        if title == page_title:
            raise Exception('Cloudflare has blocked this request. '
                            'Probably your IP is banned for this site, check in your web browser.')
    # find access denied selectors
    for selector in ACCESS_DENIED_SELECTORS:
        found_elements = driver.find_elements(By.CSS_SELECTOR, selector)
        if len(found_elements) > 0:
            raise Exception('Cloudflare has blocked this request. '
                            'Probably your IP is banned for this site, check in your web browser.')

    # find challenge by title
    challenge_found = False
    for title in CHALLENGE_TITLES:
        if title.lower() == page_title.lower():
            challenge_found = True
            logging.info("Challenge detected. Title found: " + page_title)
            break
    if not challenge_found:
        # find challenge by selectors
        for selector in CHALLENGE_SELECTORS:
            found_elements = driver.find_elements(By.CSS_SELECTOR, selector)
            if len(found_elements) > 0:
                challenge_found = True
                logging.info("Challenge detected. Selector found: " + selector)
                break

    attempt = 0
    if challenge_found:
        while True:
            try:
                attempt = attempt + 1
                driver = get_correct_window(driver, req.url)
                if attempt % 3 == 0:
                    driver = switch_to_new_tab(driver, req.url)
                    driver = get_correct_window(driver, req.url, False)
                    time.sleep(5)
                    # click_verify_direct(driver)

                # wait until the title changes
                for title in CHALLENGE_TITLES:
                    logging.debug("Waiting for title (attempt " + str(attempt) + "): " + title)
                    WebDriverWait(driver, LONG_TIMEOUT).until_not(title_is(title))

                # then wait until all the selectors disappear
                for selector in CHALLENGE_SELECTORS:
                    logging.debug("Waiting for selector (attempt " + str(attempt) + "): " + selector)
                    WebDriverWait(driver, LONG_TIMEOUT).until_not(
                        presence_of_element_located((By.CSS_SELECTOR, selector)))
                # all elements not found
                break

            except TimeoutException:
                logging.debug("Timeout waiting for selector")

                # move_mouse_randomly(driver)
                # if attempt < 4:
                # click_verify_direct(driver)
                # else:
                click_verify_with_actions(driver)

                # update the html (cloudflare reloads the page every 5 s)
                html_element = driver.find_element(By.TAG_NAME, "html")

        # waits until cloudflare redirection ends
        logging.debug("Waiting for redirect")
        # noinspection PyBroadException
        try:
            WebDriverWait(driver, SHORT_TIMEOUT).until(staleness_of(html_element))
        except Exception:
            logging.debug("Timeout waiting for redirect")

        logging.info("Challenge solved!")
        res.message = "Challenge solved!"
    else:
        logging.info("Challenge not detected!")
        res.message = "Challenge not detected!"

    challenge_res = ChallengeResolutionResultT({})
    challenge_res.url = driver.current_url
    challenge_res.status = 200  # todo: fix, selenium not provides this info
    challenge_res.cookies = driver.get_cookies()
    challenge_res.userAgent = utils.get_user_agent(driver)

    if not req.returnOnlyCookies:
        challenge_res.headers = {}  # todo: fix, selenium not provides this info
        challenge_res.response = driver.page_source

    res.result = challenge_res
    return res


def _post_request(req: V1RequestBase, driver: WebDriver):
    post_form = f'<form id="hackForm" action="{req.url}" method="POST">'
    query_string = req.postData if req.postData[0] != '?' else req.postData[1:]
    pairs = query_string.split('&')
    for pair in pairs:
        parts = pair.split('=')
        # noinspection PyBroadException
        try:
            name = unquote(parts[0])
        except Exception:
            name = parts[0]
        if name == 'submit':
            continue
        # noinspection PyBroadException
        try:
            value = unquote(parts[1])
        except Exception:
            value = parts[1]
        post_form += f'<input type="text" name="{escape(quote(name))}" value="{escape(quote(value))}"><br>'
    post_form += '</form>'
    html_content = f"""
        <!DOCTYPE html>
        <html>
        <body>
            {post_form}
            <script>document.getElementById('hackForm').submit();</script>
        </body>
        </html>"""
    driver.get("data:text/html;charset=utf-8,{html_content}".format(html_content=html_content))
    driver.start_session()
    driver.start_session()  # required to bypass Cloudflare
