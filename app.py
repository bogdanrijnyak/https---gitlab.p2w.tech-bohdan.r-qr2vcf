from flask import Flask, render_template, request, send_file, redirect, url_for
import base64
import requests
from datetime import datetime
import os
import qrcode
import sqlite3
import uuid
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session, flash
from functools import wraps
import pandas as pd
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.secret_key = os.urandom(24)



def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if session.get('role') != required_role:
                return redirect(url_for('login'))  # Redirect to an unauthorized page or handle as needed
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def generate_n_from_fn(fn):
    # Розділити повне ім'я на частини
    parts = fn.split()
    
    # Перевірити наявність префіксу (наприклад, Mr., Dr.)
    prefix = ''
    if parts[0].endswith('.'):
        prefix = parts[0]
        parts = parts[1:]
    
    # Прізвище вважається останньою частиною
    surname = parts[-1]
    
    # Ім'я - це перша частина після префіксу
    given_name = parts[0]
    
    # По-батькові відсутнє у прикладі, але якщо є, то можна обробити
    additional_names = ' '.join(parts[1:-1]) if len(parts) > 2 else ''
    
    return f"{surname};{given_name};;{prefix};"


def get_base64_file(file, url):
    if file:
        return base64.b64encode(file.read()).decode('utf-8')
    elif url:
        response = requests.get(url)
        if response.status_code == 200:
            return base64.b64encode(response.content).decode('utf-8')
        else: 
             # Fallback image as base64
            fallback_image_url = "https://st3.depositphotos.com/6672868/13701/v/450/depositphotos_137014128-stock-illustration-user-profile-icon.jpg"
            response = requests.get(fallback_image_url)
            if response.status_code == 200:
                return base64.b64encode(response.content).decode('utf-8')
            
def get_base64_from_url(url):
    if url:
        response = requests.get(url)
        if response.status_code == 200:
            return base64.b64encode(response.content).decode('utf-8')
        else: 
             # Fallback image as base64
            fallback_image_url = "https://st3.depositphotos.com/6672868/13701/v/450/depositphotos_137014128-stock-illustration-user-profile-icon.jpg"
            response = requests.get(fallback_image_url)
            if response.status_code == 200:
                return base64.b64encode(response.content).decode('utf-8')
     
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vcf_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fn TEXT,
            n TEXT,       
            bday TEXT,
            email_home TEXT,
            email_work TEXT,
            tel_home TEXT,
            tel_work TEXT,
            address_home TEXT,
            address_work TEXT,
            org TEXT,
            role TEXT,
            telegram TEXT,
            skype TEXT,
            linkedin TEXT,
            instagram TEXT,
            twitter TEXT,
            photo_base64 TEXT,
            qr_link TEXT,
            rev TEXT,
            vcfid TEXT
        )
    ''')

     # Новая таблица для отслеживания посещений
   # Обновление таблицы для хранения посещений с дополнительными полями
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS page_visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vcfid TEXT,
            visit_count INTEGER DEFAULT 0,
            last_visit TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT,
            referrer TEXT,
            UNIQUE(vcfid, ip_address)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            is_verified INTEGER DEFAULT 1,
            confirmation_code TEXT DEFAULT '1488'
        )
        
    ''')




    conn.commit()
    conn.close()

init_db()

@app.route('/')
@login_required
def form():
    username = session.get('username')
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])

def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]  # Storing the role in the session
            if session['role'] == 'admin':
                    return redirect(url_for('dashboard', username=username))
            else: 
                    return redirect(url_for('user_dashboard', username=username))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/user_dashboard/<username>')
@role_required('user')
def user_dashboard(username):
    return render_template('usrbrd.html', username=username)

@app.route('/dashboard/<username>')
@login_required
@role_required('admin')
def dashboard(username):
    return render_template('find.html', username=username)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)  # Clear the role as well
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
        except sqlite3.IntegrityError:
            flash('username already exist')
            return redirect(url_for('login'))
        finally:
            conn.close()

        return redirect(url_for('login'))

    return render_template('register.html')



@app.route('/find', methods=['GET'])
@login_required
@role_required('admin')
def find():
    email = request.args.get('email')
    return redirect(url_for('edit', email=email))

@app.route('/add')
@login_required
@role_required('admin')
def add():
    username = session.get('username')
    return render_template('form.html',username=username)


@app.route('/bulk_upload', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def bulk_upload():
    user = session.get('username')
    if request.method == 'POST':
        # Получение файла из запроса
        file = request.files.get('file')
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join('uploads', filename)
            file.save(filepath)

            # Определение формата файла и чтение данных
            if filename.endswith('.csv'):
                df = pd.read_csv(filepath)
            elif filename.endswith('.xlsx') or filename.endswith('.xls'):
                df = pd.read_excel(filepath)
            else:
                flash('Unsupported file format')
                return redirect(url_for('bulk_upload', username=user))

            # Обработка и сохранение данных в базу
            for index, row in df.iterrows():
                fn = row['fn']
                n = generate_n_from_fn(fn)
                bday = row.get('bday', '')
                email_home = row['email_home']
                email_work = row.get('email_work', '')
                tel_home = row['tel_home']
                tel_work = row.get('tel_work', '')
                address_home = row['address_home']
                address_work = row['address_work']
                org = row['org']
                title = row['role']
                telegram = row['telegram']
                skype = row['skype']
                linkedin = row['linkedin']
                instagram = row['instagram']
                twitter = row['twitter']
                
                photo_url = row.get('photo_url', '')
                photo_base64 = get_base64_from_url(photo_url)
                
                
                rev = datetime.now().strftime('%Y%m%dT%H%M%SZ')

                vcfid = str(uuid.uuid4())
                qr_url = url_for('dyn_show_page', vcfid=vcfid, _external=True)
                qr_img_filepath = os.path.join('static/output', vcfid+'.png')
    
                qr_img = qrcode.make(qr_url)
                qr_img.save(qr_img_filepath)
                conn = sqlite3.connect('database.db')
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO vcf_data (
                        fn, n, bday, email_home, email_work, tel_home, tel_work, address_home, address_work, org, role, telegram, skype, linkedin, instagram, twitter, photo_base64, qr_link, rev, vcfid
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (fn, n, bday, email_home, email_work, tel_home, tel_work, address_home, address_work, org, title, telegram, skype, linkedin, instagram, twitter, photo_base64, qr_url, rev, vcfid))
                conn.commit()
                conn.close()

            flash('Data successfully uploaded and processed.')
            return redirect(url_for('show_all'))
    return render_template('bulk_upload.html', username =user)

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_record(id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Execute the delete query
    cursor.execute('DELETE FROM vcf_data WHERE id = ?', (id,))
    conn.commit()
    conn.close()

    # Redirect to the show-all page after deletion
    flash('Record successfully deleted')
    return redirect(url_for('show_all'))

@app.route('/cancel')
@login_required
def cancel():
    username = session.get('username')
    role = session.get('role')
    if (role=='admin'):
        return redirect(url_for('dashboard',username=username))
    else: return redirect(url_for('user_dashboard',username=username))

def get_ip():
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return request.environ['REMOTE_ADDR']
    else:
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0]       
                       
@app.route('/log_visit', methods=['POST'])
def log_visit():
    data = request.get_json()
    vcfid = data.get('vcfid')
    user_agent = data.get('user_agent')
    referrer = data.get('referrer')
    ip_address = get_ip()

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM page_visits WHERE vcfid = ? AND ip_address = ?', (vcfid, ip_address))
    visit = cursor.fetchone()

    if visit:
        # Обновляем счетчик посещений и время последнего посещения
        cursor.execute('''
            UPDATE page_visits 
            SET visit_count = visit_count + 1, last_visit = CURRENT_TIMESTAMP, user_agent = ?, referrer = ?
            WHERE vcfid = ? AND ip_address = ?
        ''', (user_agent, referrer, vcfid, ip_address))
    else:
        # Вставляем новую запись для посещений
        cursor.execute('''
            INSERT INTO page_visits (vcfid, visit_count, last_visit, ip_address, user_agent, referrer)
            VALUES (?, 1, CURRENT_TIMESTAMP, ?, ?, ?)
        ''', (vcfid, ip_address, user_agent, referrer))

    conn.commit()
    conn.close()

    return '', 204  # Возвращаем пустой ответ с кодом 204 (No Content)



@app.route('/generate', methods=['POST'])
@login_required
@role_required('admin')
def generate():
    username = session.get('username')
    fn = request.form['fn']
    n = generate_n_from_fn(fn)
    bday = request.form.get('bday', '')
    email_home = request.form['email_home']
    email_work = request.form.get('email_work', '')
    tel_home = request.form['tel_home']
    tel_work = request.form.get('tel_work', '')
    address_home = request.form['address_home']
    address_work = request.form['address_work']
    org = request.form['org']
    title = request.form['role']
    telegram = request.form['telegram']
    skype = request.form['skype']
    linkedin = request.form['linkedin']
    instagram = request.form['instagram']
    twitter = request.form['twitter']
    
    photo = request.files.get('photo')
    photo_url = request.form.get('photo_url', '')
    photo_base64 = get_base64_file(photo, photo_url)
    
    rev = datetime.now().strftime('%Y%m%dT%H%M%SZ')

    vcf_content = f"""
BEGIN:VCARD
VERSION:3.0
N;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:{n}
FN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:{fn}
BDAY:{bday}
EMAIL;CHARSET=UTF-8;type=HOME:{email_home}
EMAIL;CHARSET=UTF-8;type=WORK:{email_work}
TEL;TYPE=HOME,VOICE:{tel_home}
TEL;TYPE=WORK,VOICE:{tel_work}
ADR;TYPE=HOME;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:;;;{address_home};;;
ADR;TYPE=WORK;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:;;;{address_work};;;
ORG;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:{org}
TITLE;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:{title}
PHOTO;ENCODING=BASE64;TYPE=JPEG:{photo_base64}
X-SOCIALPROFILE;TYPE=Telegram:{telegram}
X-SOCIALPROFILE;TYPE=Skype:{skype}
X-SOCIALPROFILE;TYPE=LinkedIn:{linkedin}
X-SOCIALPROFILE;TYPE=Instagram:{instagram}
X-SOCIALPROFILE;TYPE=Twitter:{twitter}
REV:{rev}
END:VCARD
    """.strip()
    
    
    vcfid = str(uuid.uuid4())
    filename = vcfid + '.html'
    qr_url = url_for('dyn_show_page', vcfid=vcfid, _external=True)

    filepath = os.path.join('static/output', filename)
    
    vcf_filename = filename.replace('.html', '.vcf')
    vcf_filepath = os.path.join('static/output/vcf', vcf_filename)
    vcf_strip = vcf_content.replace('\\n', '\\\\n').replace("'", "\\'").strip()
    fndwnld = fn + '.vcf'
    html_content_dyn = render_template('profile.html', fn=fn, title=title, tel_home=tel_home, tel_work=tel_work, email_home=email_home, email_work=email_work,
                                   address_home=address_home, address_work=address_work, org=org, telegram=telegram, skype=skype, linkedin=linkedin,
                                   instagram=instagram, twitter=twitter, photo_base64=photo_base64, vcf_filename=vcf_filename, vcf_strip=vcf_strip, fndwnld=fndwnld, vcfid = filename.replace('.html', '').rstrip('.'))

    

    os.makedirs('static/output/vcf', exist_ok=True)
#    with open(filepath.replace('.html', '.vcf'), 'w', encoding='utf-8') as file:
 #       file.write(vcf_content)

 #   with open(filepath, 'w', encoding='utf-8') as file:
 #       file.write(html_content_dyn)
    
    qr_img_filename = filename.replace('.html', '.png')

    qr_img_filename = vcfid + '.png'
    qr_img_filepath = os.path.join('static/output', qr_img_filename)
    
    qr_img = qrcode.make(qr_url)
    qr_img.save(qr_img_filepath)
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO vcf_data (
            fn, n, bday, email_home, email_work, tel_home, tel_work, address_home, address_work, org, role, telegram, skype, linkedin, instagram, twitter, photo_base64, qr_link, rev, vcfid
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (fn, n, bday, email_home, email_work, tel_home, tel_work, address_home, address_work, org, title, telegram, skype, linkedin, instagram, twitter, photo_base64, qr_url, rev, filename.replace('.html', '').rstrip('.')))
    conn.commit()
    conn.close()

    return redirect(url_for('display_qr', filename=qr_img_filename))

  
@app.route('/audit', methods=['GET'])
@login_required
def audit():
    mail = session.get('username')
    role = session.get('role')
    if (role=='admin'):
        email = request.args.get('auditEmail')
        if email:
            return redirect(url_for('visit_stats', email=email))
        else:
            return redirect(url_for('visit_stats'))
    else: 
        return redirect(url_for('visit_stats', email=mail))



@app.route('/display_qr/<filename>')
def display_qr(filename):
    user=session.get('username')
    #id = request.args.get('id')
    return render_template('display_qr.html', qr_img_filename=filename)

@app.route('/visit-stats')
@login_required
def visit_stats():
    username = session.get('username')
    email = request.args.get('email')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    if email:
        cursor.execute('''
            SELECT vcf_data.fn, vcf_data.email_home, vcf_data.email_work, page_visits.vcfid, page_visits.visit_count, 
                   page_visits.last_visit, page_visits.ip_address, page_visits.user_agent, page_visits.referrer
            FROM page_visits
            JOIN vcf_data ON page_visits.vcfid = vcf_data.vcfid
            WHERE vcf_data.email_home = ? OR vcf_data.email_work = ?
        ''', (email, email))
    else:
        cursor.execute('''
            SELECT vcf_data.fn, vcf_data.email_home, vcf_data.email_work, page_visits.vcfid, page_visits.visit_count, 
                   page_visits.last_visit, page_visits.ip_address, page_visits.user_agent, page_visits.referrer
            FROM page_visits
            JOIN vcf_data ON page_visits.vcfid = vcf_data.vcfid
        ''')

    visits = cursor.fetchall()
    conn.close()

    return render_template('visit_stats.html', visits=visits, username = username)




@app.route('/edit', methods=['GET'])
@login_required
@role_required('admin')
def edit():
    username = session.get('username')
    email = request.args.get('email')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM vcf_data WHERE email_home = ? OR email_work = ?', (email, email))
    vcf_data = cursor.fetchone()
    conn.close()
    
    if vcf_data:
        vcf_data_dict = {
            'id': vcf_data[0],
            'fn': vcf_data[1],
            'n' : vcf_data[2],
            'bday': vcf_data[3],
            'email_home': vcf_data[4],
            'email_work': vcf_data[5],
            'tel_home': vcf_data[6],
            'tel_work': vcf_data[7],
            'address_home': vcf_data[8],
            'address_work': vcf_data[9],
            'org': vcf_data[10],
            'title': vcf_data[11],
            'telegram': vcf_data[12],
            'skype': vcf_data[13],
            'linkedin': vcf_data[14],
            'instagram': vcf_data[15],
            'twitter': vcf_data[16],
            'photo_base64': vcf_data[17],
            'qr_link': vcf_data[18],
            'rev': vcf_data[19],
            'vcfid': vcf_data[20]
        }
        return render_template('edit.html', vcf_data=vcf_data_dict, username=username)
    else:
        return render_template('notfound.html')

@app.route('/update', methods=['POST'])
@login_required
@role_required('admin')
def update():
    user = session.get('username')
    id = request.form['id']
    vcfid = request.form['vcfid']
    vcfid = vcfid.replace('.html','').rstrip('.')
    qr_url = url_for('dyn_show_page', vcfid=vcfid, _external=True)
    fn = request.form['fn']
    n = generate_n_from_fn(fn)
    bday = request.form.get('bday', '')
    email_home = request.form['email_home']
    email_work = request.form.get('email_work', '')
    tel_home = request.form['tel_home']
    tel_work = request.form.get('tel_work', '')
    address_home = request.form['address_home']
    address_work = request.form.get('address_work', '')
    org = request.form['org']
    title = request.form['title']
    telegram = request.form['telegram']
    skype = request.form['skype']
    linkedin = request.form['linkedin']
    instagram = request.form['instagram']
    twitter = request.form['twitter']
    rev = datetime.now().strftime('%Y%m%dT%H%M%SZ')
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT photo_base64 FROM vcf_data WHERE id = ?', (id,))
    current_photo_base64 = cursor.fetchone()[0]

    # Обробка нового фото
    photo = request.files.get('photo')
    photo_url = request.form.get('photo_url', '')
    photo_base64 = get_base64_file(photo, photo_url)

    # Якщо нове фото не завантажено, використовувати поточне значення
    if not photo_base64:
        photo_base64 = current_photo_base64

    cursor.execute('''
        UPDATE vcf_data SET 
        fn = ?, n = ?, bday = ?, email_home = ?, email_work = ?, tel_home = ?, tel_work = ?, address_home = ?, address_work = ?, 
        org = ?, role = ?, telegram = ?, skype = ?, linkedin = ?, instagram = ?, twitter = ?, photo_base64 = ?, qr_link =?, rev = ?, vcfid = ?
        WHERE id = ?
    ''', (fn, n, bday, email_home, email_work, tel_home, tel_work, address_home, address_work, org, title, telegram, skype, linkedin, instagram, twitter, photo_base64, qr_url, rev, vcfid, id))
    conn.commit()
    conn.close()
    
    vcf_content = f"""
BEGIN:VCARD
VERSION:3.0
N;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:{n}
FN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:{fn}
BDAY:{bday}
EMAIL;CHARSET=UTF-8;type=HOME:{email_home}
EMAIL;CHARSET=UTF-8;type=WORK:{email_work}
TEL;TYPE=HOME,VOICE:{tel_home}
TEL;TYPE=WORK,VOICE:{tel_work}
ADR;TYPE=HOME;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:;;;{address_home};;;
ADR;TYPE=WORK;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:;;;{address_work};;;
ORG;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:{org}
TITLE;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:{title}
PHOTO;ENCODING=BASE64;TYPE=JPEG:{photo_base64}
X-SOCIALPROFILE;TYPE=Telegram:{telegram}
X-SOCIALPROFILE;TYPE=Skype:{skype}
X-SOCIALPROFILE;TYPE=LinkedIn:{linkedin}
X-SOCIALPROFILE;TYPE=Instagram:{instagram}
X-SOCIALPROFILE;TYPE=Twitter:{twitter}
REV:{rev}
END:VCARD
    """.strip()
    
   
    vcf_strip = vcf_content.replace('\\n', '\\\\n').replace("'", "\\'").strip()
    
    filename = vcfid +'.html'
    filepath = os.path.join('static/output', filename)
    
    vcf_filename = filename.replace('.html', '.vcf')
    vcf_filepath = os.path.join('static/output/vcf', vcf_filename)

  #  os.makedirs('static/output/vcf', exist_ok=True)
   #with open(filepath.replace('.html', '.vcf'), 'w', encoding='utf-8') as file:
   #     file.write(vcf_content)
    fndwnld = fn + '.vcf'

    html_content_dyn = render_template('profile.html', fn=fn, title=title, tel_home=tel_home, tel_work=tel_work, email_home=email_home, email_work=email_work,
                                   address_home=address_home, address_work=address_work, org=org, telegram=telegram, skype=skype, linkedin=linkedin,
                                   instagram=instagram, twitter=twitter, photo_base64=photo_base64, vcf_strip=vcf_strip, vcf_filename = vcf_filename, fndwnld=fndwnld, vcfid = vcfid.replace('.html', '').rstrip('.'))


  #  with open(filepath, 'w', encoding='utf-8') as file:
   #     file.write(html_content_dyn)

    qr_img_filename = vcfid + '.png'
    qr_img_filepath = os.path.join('static/output', qr_img_filename)
    
    qr_img = qrcode.make(qr_url)
    qr_img.save(qr_img_filepath)

    return redirect(url_for('display_qr', filename=qr_img_filename, username = user))

@app.route('/show')
def dyn_show_page():
    vcfid = request.args.get('vcfid')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM vcf_data WHERE vcfid = ?', (vcfid,))
    vcf_data = cursor.fetchone()
    conn.close()
    
    if vcf_data:
       
            id = vcf_data[0]
            fn =  vcf_data[1]
            n = vcf_data[2]
            bday= vcf_data[3]
            email_home= vcf_data[4]
            email_work= vcf_data[5]
            tel_home= vcf_data[6]
            tel_work= vcf_data[7]
            address_home= vcf_data[8]
            address_work= vcf_data[9]
            org= vcf_data[10]
            title= vcf_data[11]
            telegram= vcf_data[12]
            skype= vcf_data[13]
            linkedin= vcf_data[14]
            instagram= vcf_data[15]
            twitter= vcf_data[16]
            photo_base64= vcf_data[17]
            qr_link= vcf_data[18]
            rev= vcf_data[19]
            vcfid= vcf_data[20]
            fndwnld = fn + '.vcf'

    
            vcf_content = f"""
BEGIN:VCARD
VERSION:3.0
N;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:{n}
FN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:{fn}
BDAY:{bday}
EMAIL;CHARSET=UTF-8;type=HOME:{email_home}
EMAIL;CHARSET=UTF-8;type=WORK:{email_work}
TEL;TYPE=HOME,VOICE:{tel_home}
TEL;TYPE=WORK,VOICE:{tel_work}
ADR;TYPE=HOME;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:;;;{address_home};;;
ADR;TYPE=WORK;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:;;;{address_work};;;
ORG;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:{org}
TITLE;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:{title}
PHOTO;ENCODING=BASE64;TYPE=JPEG:{photo_base64}
X-SOCIALPROFILE;TYPE=Telegram:{telegram}
X-SOCIALPROFILE;TYPE=Skype:{skype}
X-SOCIALPROFILE;TYPE=LinkedIn:{linkedin}
X-SOCIALPROFILE;TYPE=Instagram:{instagram}
X-SOCIALPROFILE;TYPE=Twitter:{twitter}
REV:{rev}
END:VCARD
    """.strip()
            vcf_strip = vcf_content.replace('\\n', '\\\\n').replace("'", "\\'").strip()
            vcf_filename = fndwnld

            return render_template('profile.html', fn=fn, title=title, tel_home=tel_home, tel_work=tel_work, email_home=email_home, email_work=email_work,
                                   address_home=address_home, address_work=address_work, org=org, telegram=telegram, skype=skype, linkedin=linkedin,
                                   instagram=instagram, twitter=twitter, photo_base64=photo_base64, vcf_strip=vcf_strip, vcf_filename = vcf_filename, fndwnld=fndwnld, vcfid = vcfid.replace('.html', ''))

    else:
        return render_template('notfound.html')



@app.route('/show-all')
@login_required
@role_required('admin')
def show_all():
    username = session.get('username')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM vcf_data')
    all_data = cursor.fetchall()
    conn.close()
    return render_template('show_all.html', all_data=all_data, username = username)


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
