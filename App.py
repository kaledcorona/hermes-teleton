

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy

from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename
import hashlib
import json
import binascii
import sqlite3

from Crypto.PublicKey import RSA




app = Flask(__name__)
app.config['SECRET_KEY'] = '!b8^cw1u#6gg)=yj7=x1(^8(z4-9holmnsz%alvf%jd^2&v4d='
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database2.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

login_manager = LoginManager(app)
login_manager.login_view = "login"
db = SQLAlchemy(app)

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model, UserMixin):
    __tablename__ = 'usuarios_sistema'
    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(80), nullable=False)
    id_per = db.Column(db.String(256), unique=True, nullable=False)
    contraseña = db.Column(db.String(128), nullable=False)
    departamento = db.Column(db.String(80), nullable=False)
    n = db.Column(db.String, nullable=False)
    e_public = db.Column(db.String, nullable=False)
    d_priv = db.Column(db.String, nullable=False)
    
    def __repr__(self):
        return f'<User {self.id_per}>'
    
    def set_password(self, contraseña):
        self.contraseña = generate_password_hash(contraseña)
        
    def check_password(self, contraseña):
        return check_password_hash(self.contraseña, contraseña)
    
    def save(self):
        if not self.id:
            db.session.add(self)
        db.session.commit()
    
    @staticmethod
    def get_by_id(id):
        return User.query.get(id)
    
    @staticmethod
    def get_by_ID(id_per):
        return User.query.filter_by(id_per=id_per).first()
    
    @staticmethod
    def get_by_usuario(usuario):
        return User.query.filter_by(usuario=usuario).first()

db.create_all()


def get_db_connection():
    conn = sqlite3.connect('database2.db')
    conn.row_factory = sqlite3.Row
    return conn

@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(int(user_id))




@app.route('/',methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('menu'))
    
    if request.method == 'POST':
        user = User.get_by_ID(request.form['user'])
        if user is not None and user.check_password(request.form['password']):
            login_user(user, remember=request.form['remember'])
            next_page = request.args.get('next')
            
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('firmar')
            return redirect(next_page)
    return render_template('index.html')

@app.route("/signup/", methods=["GET", "POST"])
def show_signup_form():
    if current_user.is_authenticated:
        return redirect(url_for('firmar'))
    
    error = None
    
    if request.method == 'POST':
        usuario = request.form['user']
        ID = request.form['userID']
        departamento = request.form['dpto']
        contraseña = request.form['password']
        
        user = User.get_by_ID(ID)
        usern = User.get_by_usuario(usuario)
        
        if user is not None:
            error = f'El ID {ID} ya está siendo utilizado por otro usuario'
            flash(error)
        
        elif usern is not None:
            error = f'El nombre {usuario} ya está siendo utilizado por otro usuario'
            flash(error)
        else:
            
            
            keyPair = RSA.generate(bits=1024)
            
            user = User(usuario=usuario,
                        id_per=ID,
                        departamento=departamento,
                        n = str(keyPair.n),
                        e_public = str(keyPair.e),
                        d_priv = str(keyPair.d)
                        )
            
            user.set_password(contraseña)
            user.save()
            
            login_user(user,remember=True)
            next_page = request.args.get('next', None)
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('menu')
            return redirect(next_page)
    return render_template("signup.html")

@app.route("/firma_EXITOSA/")
def exitoFirma():
    return "FIRMA EXITOSA"

@app.route("/verificacion_EXITOSA/")
def exitoVerificacion():
    usuarios_que_firmaron = request.args['usuarios_que_firmaron']  # counterpart for url_for()
    usuarios_que_firmaron = session['usuarios_que_firmaron'] 
    return render_template('verificado.html',usuarios_que_firmaron=usuarios_que_firmaron)

@app.route("/verificacion_FALLIDA/")
def fracasoVerificacion():
    return "EL DOCUMENTO NO ESTA FIRMADO"


@app.route("/menu/", methods=["GET", "POST"])
@login_required
def menu():
    return render_template('menu.html')


@app.route("/menu/firmar", methods=["GET", "POST"])
@login_required
def firmar():

    if request.method == 'POST':
        
        user = User.get_by_ID(current_user.id_per)
        
        if user.check_password(request.form['gpsswd1']):
            
            if request.method == 'POST':
                
                doc = request.files['gfile']
                ruta_archivo = './documentos_recibidos/'
                doc.save(ruta_archivo+secure_filename(doc.filename))
                
                docRead = open(ruta_archivo+secure_filename(doc.filename),'rb').read().hex()
                
                doc_hash = hashlib.sha512(str(docRead).encode('utf-8')).hexdigest()
                
                doc_int = int.from_bytes( binascii.unhexlify(doc_hash),byteorder='big')
                
                
                conn = get_db_connection()
                cursor = conn.cursor()
                data = cursor.execute('SELECT e_public, n, d_priv FROM usuarios_sistema WHERE id_per = (?)',(current_user.id_per,)).fetchall()
                
                e_public = data[0][0]
                n = data[0][1]+'A'
                d_priv = data[0][2]+'A'
                
                n_n = n[:-1]
                d_priv_n = d_priv[:-1]
                
                
                d_priv_int= int(d_priv_n)
                n_int = int(n_n)
                
                firma = hex(pow(doc_int, d_priv_int, n_int))


                doc_name = secure_filename(doc.filename)
                
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute('''
                               INSERT INTO firmas (document_id,
                                                   document_name,
                                                   firma,
                                                   id_per,
                                                   usuario,
                                                   e_public,
                                                   n,
                                                   d_priv
                                                   )
                               VALUES (?,?,?,?,?,?,?,?)
                               ''',(doc_hash,doc_name,firma,current_user.id_per,current_user.usuario,e_public,n,d_priv))

                conn.commit()
                conn.close()
                
                next_page = request.args.get('next')

                return redirect(url_for('exitoFirma'))
    
                if not next_page or url_parse(next_page).netloc != '':
                    next_page = url_for('exitoFirma')
                return redirect(next_page)

    return render_template(url_for('menu'))

@app.route("/menu/verificar", methods=["GET", "POST"])
@login_required
def verificar():

    if request.method == 'POST':
        
        user = User.get_by_ID(current_user.id_per)
        
        if user.check_password(request.form['gpsswd2']):
            
            if request.method == 'POST':
                
                doc = request.files['vfile']
                ruta_archivo = './documentos_verificados/'
                doc.save(ruta_archivo+secure_filename(doc.filename))
                docRead = open(ruta_archivo+secure_filename(doc.filename),'rb').read().hex()
                
                doc_hash = hashlib.sha512(str(docRead).encode('utf-8')).hexdigest()
                
                doc_int = int.from_bytes(binascii.unhexlify(doc_hash),byteorder='big')


                conn = get_db_connection()
                cursor = conn.cursor()
                data = cursor.execute('SELECT usuario, e_public, n, firma FROM firmas WHERE document_id = (?)',(doc_hash,)).fetchall()
                conn.close()
                
                
                llaves = {}
                
                ver_binary = 0
                for fila in data:
                    e = fila[1]

                    n = fila[2]
                    n_n = n[:-1]
                
                    llaves[fila[0]] = (e,n_n,fila[3])

                    hashFromSignature = pow(int(fila[3],base=16), int(e), int(n_n))
                    if hashFromSignature == doc_int:
                        ver_binary = 1
                    else:
                        ver_binary = 0
                        
                if ver_binary == 1:
                
                    next_page = request.args.get('next')
                    
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    quien_firmo = cursor.execute('SELECT usuario FROM firmas WHERE document_id = (?)',(doc_hash,)).fetchall()
                    
                    conn.close()
                    
                    usuarios_que_firmaron = []
                    for i in quien_firmo:
                        for j in i:
                           usuarios_que_firmaron.append(j)
                           
                    usuarios_que_firmaron = json.dumps(usuarios_que_firmaron)
                    session['usuarios_que_firmaron'] = usuarios_que_firmaron
                    
                    return redirect(url_for('exitoVerificacion',usuarios_que_firmaron=usuarios_que_firmaron))
        
                    if not next_page or url_parse(next_page).netloc != '':
                        next_page = url_for('exitoVerificacion')
                    return redirect(next_page)
                else:
                    
                    next_page = request.args.get('next')

                    return redirect(url_for('fracasoVerificacion'))
        
                    if not next_page or url_parse(next_page).netloc != '':
                        next_page = url_for('fracasoVerificacion')
                    return redirect(next_page)
                    

    return render_template(url_for("menu"))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/help')
def help():
    return render_template('help.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(port = 3000, debug=True)

# -*- coding: utf-8 -*-

