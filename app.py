from flask import Flask, render_template, request, jsonify, redirect, send_file, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import re
import random
import string
import os
from zxcvbn import zxcvbn

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///admin.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24)
db = SQLAlchemy(app)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f'<Admin {self.email}>'

app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def charger_dictionnaire(fichier_dictionnaire):
    with open(fichier_dictionnaire, "r", encoding="latin-1") as fichier:
        lignes = fichier.readlines()
        dictionnaire = set(ligne.strip() for ligne in lignes)
    return dictionnaire

fichier_dictionnaire = "rockyou.txt"
dictionnaire_mots_de_passe = charger_dictionnaire(fichier_dictionnaire)

def evaluer_mot_de_passe(password, longueur_min=8, inclure_chiffres=False, inclure_majuscules=False, inclure_minuscules=False, inclure_symboles=False):
    length_score = (len(password) >= longueur_min)
    uppercase_score = bool(re.search(r'[A-Z]', password)) or inclure_majuscules
    lowercase_score = bool(re.search(r'[a-z]', password)) or inclure_minuscules
    digit_score = bool(re.search(r'\d', password)) or inclure_chiffres
    special_char_score = bool(re.search(r'[^a-zA-Z0-9]', password)) or inclure_symboles
    in_dictionary = password in dictionnaire_mots_de_passe
    is_strong = length_score and uppercase_score and lowercase_score and digit_score and special_char_score and not in_dictionary

    feedback = []
    if not length_score:
        feedback.append(f'Inclure au moins {longueur_min} caractères.')
    if not uppercase_score:
        feedback.append('Inclure au moins une majuscule.')
    if not lowercase_score:
        feedback.append('Inclure au moins une minuscule.')
    if not digit_score:
        feedback.append('Inclure au moins un chiffre.')
    if not special_char_score:
        feedback.append('Inclure au moins un symbole.')
    if in_dictionary:
        feedback.append('Le mot de passe ne doit pas être un mot de passe commun.')

    
    # Utilisation de zxcvbn pour obtenir le temps de cassage
    try:
        zxcvbn_result = zxcvbn(password)
        time_to_crack = zxcvbn_result['crack_times_display']['offline_slow_hashing_1e4_per_second']
        time_to_crack = traduire_temps_de_craquage(time_to_crack)  # Traduire le temps en français
    except Exception as e:
        time_to_crack = "Erreur d'analyse"
        

    if is_strong:
        return {
            'isStrong': True,
            'timeToCrack': time_to_crack
        }
    else:
        suggested_passwords = ameliorer_mot_de_passe(password, longueur_min, inclure_chiffres, inclure_majuscules, inclure_minuscules, inclure_symboles)
        return {
            'isStrong': False,
            'isCommon': in_dictionary,
            'suggestedPasswords': suggested_passwords,
            'feedback': feedback,
            'timeToCrack': time_to_crack
        }

def ameliorer_mot_de_passe(mot_de_passe_faible, longueur_min=8, inclure_chiffres=False, inclure_majuscules=False, inclure_minuscules=False, inclure_symboles=False):
    caracteres = string.ascii_letters + string.digits + "!@#$%^&*()"
    mots_de_passe_ameliores = []
    length_score = len(mot_de_passe_faible) >= longueur_min
    uppercase_score = bool(re.search(r'[A-Z]', mot_de_passe_faible)) or inclure_majuscules
    lowercase_score = bool(re.search(r'[a-z]', mot_de_passe_faible)) or inclure_minuscules
    digit_score = bool(re.search(r'\d', mot_de_passe_faible)) or inclure_chiffres
    special_char_score = bool(re.search(r'[^a-zA-Z0-9]', mot_de_passe_faible)) or inclure_symboles
    sequences_lettres = re.findall(r'[a-zA-Z]+', mot_de_passe_faible)

    while len(mots_de_passe_ameliores) < 4:
        mot_de_passe_ameliore = mot_de_passe_faible
        car_score = uppercase_score or lowercase_score
        if not car_score:
            mot_de_passe_ameliore += random.choice(string.ascii_uppercase)
            mot_de_passe_ameliore += random.choice(string.ascii_lowercase)

        if not uppercase_score:
            for i in range(len(sequences_lettres)):
                if len(sequences_lettres[i]) > 1:
                    mot_de_passe_ameliore = mot_de_passe_ameliore.replace(sequences_lettres[i][0], sequences_lettres[i][0].upper(), 1)
                    break
            else:
                mot_de_passe_ameliore += random.choice(string.ascii_uppercase)

        if not lowercase_score:
            for i in range(len(sequences_lettres)):
                if len(sequences_lettres[i]) > 1:
                    mot_de_passe_ameliore = mot_de_passe_ameliore.replace(sequences_lettres[i][0], sequences_lettres[i][0].lower(), 1)
                    break
            else:
                mot_de_passe_ameliore += random.choice(string.ascii_lowercase)

        if not digit_score:
            mot_de_passe_ameliore += random.choice(string.digits)
        if not special_char_score:
            mot_de_passe_ameliore += random.choice("!@#$%^&*()")

        if len(mot_de_passe_ameliore) < longueur_min:
            mot_de_passe_ameliore += "".join(random.choice(caracteres) for _ in range(longueur_min - len(mot_de_passe_ameliore)))

        while mot_de_passe_ameliore in dictionnaire_mots_de_passe:
            mot_de_passe_ameliore += "".join(random.choice(caracteres))

        if mot_de_passe_ameliore not in mots_de_passe_ameliores:
            mots_de_passe_ameliores.append(mot_de_passe_ameliore)

    return mots_de_passe_ameliores

def traduire_temps_de_craquage(temps_en_anglais):
    traductions = {
        "less than a second": "moins d'une seconde",
        "instant": "instantané",
        "seconds": "secondes",
        "minutes": "minutes",
        "hours": "heures",
        "days": "jours",
        "months": "mois",
        "years": "années",
        "centuries": "siècles"
    }

    for anglais, francais in traductions.items():
        if anglais in temps_en_anglais:
            return temps_en_anglais.replace(anglais, francais)

    return temps_en_anglais  # Retourne le texte original si aucune traduction n'est trouvée


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/evaluate-password', methods=['POST'])
def evaluate_password_route():
    password = request.json['password']
    evaluation_result = evaluer_mot_de_passe(password)
    return jsonify(evaluation_result)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)
        with open(filepath, 'r') as f:
            passwords = f.read().splitlines()
        evaluation_results = []
        for pw in passwords:
            result = evaluer_mot_de_passe(pw)
            evaluation_results.append((pw, result))

        results_filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'results.csv')
        with open(results_filepath, 'w') as results_file:
            for pw, result in evaluation_results:
                if 'suggestedPasswords' in result:
                    suggestions = '|'.join(result['suggestedPasswords'])
                else:
                    suggestions = ''
                line = f"{pw},{result['isStrong']},{result.get('isCommon', False)},{suggestions},{result['timeToCrack']}\n"
                results_file.write(line)

        return render_template('results.html', results=evaluation_results)

@app.route('/download-results', methods=['GET'])
def download_results():
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'results.csv')
    return send_file(filepath, as_attachment=True, download_name='results.csv')

@app.route('/download-admin-results', methods=['GET'])
def download_admin_results():
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'admin_results.csv')
    return send_file(filepath, as_attachment=True, download_name='admin_results.csv')

def validation(email, password):
    admin = Admin.query.filter_by(email=email).first()
    if admin and check_password_hash(admin.password, password):
        return True
    return False

@app.route("/login", methods=['POST', 'GET'])
def login1():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if email == 'admin@gmail.com' and password == 'admin':
            return redirect(url_for('gestionadmin'))
        elif validation(email, password):
            return redirect(url_for('admin_page'))
        else:
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login1'))
    return render_template('login.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin_page():
    if request.method == 'POST':
        if 'fileToUpload' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        file = request.files['fileToUpload']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        passwords = file.read().decode('utf-8').splitlines()
        criteria = {
            'length': int(request.form.get('nomber_caractere', 8)),
            'include_numbers': request.form.get('includeNumbers') != 'on',
            'include_uppercase': request.form.get('includeUppercase') != 'on',
            'include_lowercase': request.form.get('includeLowercase') != 'on',
            'include_symbols': request.form.get('includeSymbols') != 'on'
        }

        evaluation_results = []
        for pw in passwords:
            result = evaluer_mot_de_passe(pw, longueur_min=criteria['length'], inclure_chiffres=False, inclure_majuscules=False, inclure_minuscules=False, inclure_symboles=False)
            if result['isStrong']:
                result['isStrong']='fort'
                evaluation_results.append((pw, result))
            else:
                # If password is weak, reevaluate with all criteria included
                result_weak = evaluer_mot_de_passe(pw, longueur_min=criteria['length'], inclure_chiffres=criteria['include_numbers'],
                                          inclure_majuscules=criteria['include_uppercase'], inclure_minuscules=criteria['include_lowercase'],
                                          inclure_symboles=criteria['include_symbols'])
                
                if result_weak['isStrong']:
                    result['isStrong'] = 'moyen'
                else:
                    result['isStrong'] = 'faible'
                evaluation_results.append((pw, result))

        results_filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'admin_results.csv')
        with open(results_filepath, 'w') as results_file:
            for pw, result in evaluation_results:
                if 'suggestedPasswords' in result:
                    suggestions = '|'.join(result['suggestedPasswords'])
                    feedback = '|'.join(result['feedback']) if 'feedback' in result else ''
               
                else:
                    suggestions = ''
                    feedback=''
                line = f"{pw},{result['isStrong']},{result.get('isCommon', False)},{result['timeToCrack']},{feedback},{suggestions}\n"
                results_file.write(line)

        return render_template('pageAdmin.html', results=evaluation_results, criteria=criteria)
    return render_template('pageAdmin.html')

@app.route("/gestionadmin", methods=["GET", "POST"])
def gestionadmin():
    if request.method == "POST":
        action = request.form.get("action")
        email = request.form.get("email")
        password = request.form.get("password")
        if action == "add":
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_admin = Admin(email=email, password=hashed_password)
            db.session.add(new_admin)
            db.session.commit()
            flash("Admin added successfully", "success")
        elif action == "delete":
            admin = Admin.query.filter_by(email=email).first()
            if admin:
                db.session.delete(admin)
                db.session.commit()
                flash("Admin deleted successfully", "success")
            else:
                flash("Admin not found", "danger")
    admins = Admin.query.all()
    return render_template("gestionadmin.html", admins=admins)

@app.route('/get-admins', methods=['GET'])
def get_admins():
    admins = Admin.query.all()
    admin_list = [{'id': admin.id, 'email': admin.email} for admin in admins]
    return jsonify({'admins': admin_list})

@app.route('/add-admin', methods=['POST'])
def add_admin():
    data = request.get_json()
    email = data['email']
    password = data['password']

    existing_admin = Admin.query.filter_by(email=email).first()
    if existing_admin:
        return jsonify({'error': 'Email already exists'})

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    new_admin = Admin(email=email, password=hashed_password)

    db.session.add(new_admin)
    db.session.commit()

    return jsonify({'message': 'Admin added successfully'})

@app.route('/delete-admin', methods=['POST'])
def delete_admin():
    data = request.get_json()
    email = data['email']

    admin = Admin.query.filter_by(email=email).first()
    if admin:
        db.session.delete(admin)
        db.session.commit()
        return jsonify({'success': True, 'message': f'Admin {email} deleted successfully'})
    else:
        return jsonify({'error': 'Admin not found'})

@app.route('/check-admin', methods=['POST'])
def check_admin():
    data = request.get_json()
    email = data['email']
    password = data['password']
    if email == 'admin@gmail.com' and password == 'admin':
        return jsonify({'isValid': True, 'redirect': url_for('gestionadmin')})

    admin = Admin.query.filter_by(email=email).first()
    if admin and check_password_hash(admin.password, password):
        return jsonify({'isValid': True, 'redirect': url_for('admin_page')})
    else:
        return jsonify({'isValid': False})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure this line is added to create the database schema
    app.run(debug=True)
