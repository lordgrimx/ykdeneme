from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy 
from datetime import datetime, timedelta
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__, static_url_path='/static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecommerce.db'
app.config['SECRET_KEY'] = 'gizli_anahtar'
app.config['JWT_SECRET_KEY'] = 'jwt-gizli-anahtar'  # JWT için ayrı bir gizli anahtar
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)  # Token geçerlilik süresi
jwt = JWTManager(app)
db = SQLAlchemy(app)

# Sepet yönetimi için yardımcı fonksiyonlar
def sepet_olustur():
    if 'sepet' not in session:
        session['sepet'] = {}
    return session['sepet']

def sepet_toplam():
    sepet = sepet_olustur()
    toplam = 0
    for urun_id, adet in sepet.items():
        urun = Urun.query.get(int(urun_id))
        if urun:
            toplam += urun.fiyat * adet
    return toplam

# Veritabanı modelleri
class Urun(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    isim = db.Column(db.String(100), nullable=False)
    aciklama = db.Column(db.Text, nullable=False)
    fiyat = db.Column(db.Float, nullable=False)
    stok = db.Column(db.Integer, nullable=False)
    resim_url = db.Column(db.String(200))
    eklenme_tarihi = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Ana sayfa
@app.route('/')
def ana_sayfa():
    urunler = Urun.query.all()
    return render_template('index.html', urunler=urunler)

# Ürün detay sayfası
@app.route('/urun/<int:urun_id>')
def urun_detay(urun_id):
    urun = Urun.query.get_or_404(urun_id) # Select * from urun where id = urun_id
    return render_template('urun_detay.html', urun=urun)

# Sepet işlemleri
@app.route('/sepet')
def sepet_goster():
    sepet = sepet_olustur()
    sepet_urunleri = []
    for urun_id, adet in sepet.items():
        urun = Urun.query.get(int(urun_id)) # Select * from urun where id = urun_id
        if urun:
            sepet_urunleri.append({
                'urun': urun,
                'adet': adet,
                'toplam': urun.fiyat * adet
            })
    return render_template('sepet.html', sepet_urunleri=sepet_urunleri, toplam=sepet_toplam())

@app.route('/sepet/ekle/<int:urun_id>', methods=['POST'])
def sepete_ekle(urun_id):
    urun = Urun.query.get_or_404(urun_id)
    sepet = sepet_olustur()
    
    adet = int(request.form.get('adet', 1))
    
    if str(urun_id) in sepet:
        sepet[str(urun_id)] += adet
    else:
        sepet[str(urun_id)] = adet
    
    session.modified = True
    flash(f'{urun.isim} sepete eklendi!', 'success')
    return redirect(request.referrer or url_for('ana_sayfa'))

@app.route('/sepet/guncelle/<int:urun_id>', methods=['POST'])
def sepet_guncelle(urun_id):
    sepet = sepet_olustur()
    yeni_adet = int(request.form.get('adet', 0))
    
    if yeni_adet > 0:
        sepet[str(urun_id)] = yeni_adet
    else:
        sepet.pop(str(urun_id), None)
    
    session.modified = True
    return redirect(url_for('sepet_goster'))

@app.route('/sepet/sil/<int:urun_id>')
def sepetten_sil(urun_id):
    sepet = sepet_olustur()
    if str(urun_id) in sepet:
        del sepet[str(urun_id)]
        session.modified = True
    return redirect(url_for('sepet_goster'))

# Login sayfası
@app.route('/login')
def login_page():
    return render_template('login.html')

# Kullanıcı kaydı
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"msg": "Bu kullanıcı adı zaten kullanımda"}), 400
        
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"msg": "Bu email zaten kullanımda"}), 400
    
    user = User(
        username=data['username'],
        email=data['email']
    )
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({"msg": "Kullanıcı başarıyla oluşturuldu"}), 201

# Kullanıcı girişi
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    
    if user and user.check_password(data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify({
            "msg": "Giriş başarılı",
            "access_token": access_token,
            "is_admin": user.is_admin
        }), 200
    
    return jsonify({"msg": "Geçersiz kullanıcı adı veya şifre"}), 401

# Kullanıcı profili
@app.route('/profile')
@jwt_required()
def profile():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            return jsonify({"msg": "Kullanıcı bulunamadı"}), 404
            
        return jsonify({
            "username": user.username,
            "email": user.email,
            "created_at": user.created_at.isoformat()
        }), 200
    except Exception as e:
        return jsonify({"msg": "Bir hata oluştu", "error": str(e)}), 500

# Admin panel koruması
@app.route('/admin')
@jwt_required()
def admin_panel():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user.is_admin:
        return jsonify({"msg": "Bu sayfaya erişim yetkiniz yok"}), 403
        
    urunler = Urun.query.all()
    return render_template('admin/panel.html', urunler=urunler)

# Yeni ürün ekleme
@app.route('/admin/urun/ekle', methods=['GET', 'POST'])
@jwt_required()
def urun_ekle():
    if request.method == 'POST':
        yeni_urun = Urun(
            isim=request.form['isim'],
            aciklama=request.form['aciklama'],
            fiyat=float(request.form['fiyat']),
            stok=int(request.form['stok']),
            resim_url=request.form['resim_url']
        )
        db.session.add(yeni_urun)
        db.session.commit()
        flash('Ürün başarıyla eklendi!', 'success')
        return redirect(url_for('admin_panel'))
    return render_template('admin/urun_ekle.html')

# Ürün düzenleme
@app.route('/admin/urun/duzenle/<int:urun_id>', methods=['GET', 'POST'])
@jwt_required()
def urun_duzenle(urun_id):
    urun = Urun.query.get_or_404(urun_id)
    if request.method == 'POST':
        urun.isim = request.form['isim']
        urun.aciklama = request.form['aciklama']
        urun.fiyat = float(request.form['fiyat'])
        urun.stok = int(request.form['stok'])
        urun.resim_url = request.form['resim_url']
        db.session.commit()
        flash('Ürün başarıyla güncellendi!', 'success')
        return redirect(url_for('admin_panel'))
    return render_template('admin/urun_duzenle.html', urun=urun)

# Ürün silme
@app.route('/admin/urun/sil/<int:urun_id>')
@jwt_required()
def urun_sil(urun_id):
    urun = Urun.query.get_or_404(urun_id)
    db.session.delete(urun)
    db.session.commit()
    flash('Ürün başarıyla silindi!', 'success')
    return redirect(url_for('admin_panel'))

if __name__ == '__main__':
    app.run(debug=True)
