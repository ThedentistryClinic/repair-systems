import os
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_super_secret_key_change_this'

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- Config Database (รองรับทั้ง PostgreSQL บน Render และ SQLite บน Local) ---
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///intranet.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Database Models ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')
    documents = db.relationship('Document', backref='uploader', lazy=True)

class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    min_role = db.Column(db.String(20), default='user')
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())

class ExternalLink(db.Model):
    __tablename__ = 'external_links'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text, nullable=True)
    min_role = db.Column(db.String(20), default='user')

# ฟังก์ชันสร้างตารางและข้อมูลเริ่มต้นอัตโนมัติ
def init_db():
    with app.app_context():
        db.create_all()
        
        # สร้าง User เริ่มต้น (ถ้าระบบยังว่างอยู่)
        if User.query.count() == 0:
            admin_pass = generate_password_hash('123456')
            staff_pass = generate_password_hash('123456')
            user_pass = generate_password_hash('123456')
            
            db.session.add_all([
                User(username='admin', password=admin_pass, role='admin'),
                User(username='staff1', password=staff_pass, role='staff'),
                User(username='user1', password=user_pass, role='user')
            ])
            
            # เพิ่มลิงก์ตัวอย่าง
            db.session.add_all([
                ExternalLink(title='ระบบ ERP องค์กร', url='https://example.com', description='ระบบบัญชีและทรัพยากรบุคคล', min_role='user'),
                ExternalLink(title='ระบบแจ้งซ่อม IT', url='https://example.com', description='แจ้งปัญหาคอมพิวเตอร์และอุปกรณ์', min_role='user')
            ])
            db.session.commit()

# กำหนดระดับสิทธิ์ (Role Hierarchy)
ROLE_HIERARCHY = {'user': 1, 'staff': 2, 'admin': 3}

def has_permission(user_role, min_role):
    return ROLE_HIERARCHY.get(user_role, 0) >= ROLE_HIERARCHY.get(min_role, 0)

# 1. หน้า Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))
        else:
            flash('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# 3, 4, 5. หน้า Dashboard (แสดงเอกสาร, ลิงก์, ค้นหา, อัปโหลด)
@app.route('/', methods=['GET'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    current_role = session['role']
    search_query = request.args.get('q', '').strip()
    
    # เงื่อนไขสิทธิ์การมองเห็นตาม Role
    allowed_roles = ['user']
    if current_role in ['staff', 'admin']:
        allowed_roles.append('staff')
    if current_role == 'admin':
        allowed_roles.append('admin')
        
    # ค้นหาเอกสาร (ข้อ 5) และกรองตาม Role
    doc_query = Document.query.filter(Document.min_role.in_(allowed_roles))
    if search_query:
        doc_query = doc_query.filter(Document.title.like(f'%{search_query}%'))
    documents = doc_query.order_by(Document.id.desc()).all()
    
    # ดึงลิงก์ภายนอกตามสิทธิ์ (ข้อ 4)
    links = ExternalLink.query.filter(ExternalLink.min_role.in_(allowed_roles)).all()
    
    return render_template('dashboard.html', documents=documents, links=links, search_query=search_query)

# 3. อัปโหลดเอกสาร (สำหรับ Staff / Admin)
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session or not has_permission(session['role'], 'staff'):
        return "Unauthorized", 403
        
    if 'file' not in request.files:
        return redirect(url_for('dashboard'))
        
    file = request.files['file']
    title = request.form.get('title', file.filename)
    min_role = request.form.get('min_role', 'user')
    
    if file.filename == '':
        return redirect(url_for('dashboard'))
        
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        new_doc = Document(
            title=title,
            filename=filename,
            min_role=min_role,
            uploaded_by=session['user_id']
        )
        db.session.add(new_doc)
        db.session.commit()
        
    return redirect(url_for('dashboard'))

# 3. ดาวน์โหลดเอกสาร (ตรวจสอบสิทธิ์ก่อนโหลด)
@app.route('/download/<int:doc_id>')
def download_file(doc_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    doc = Document.query.get(doc_id)
    
    if not doc:
        return "Document not found", 404
        
    # เช็คสิทธิ์การโหลด
    if not has_permission(session['role'], doc.min_role):
        return "คุณไม่มีสิทธิ์ดาวน์โหลดเอกสารฉบับนี้", 403
        
    return send_from_directory(app.config['UPLOAD_FOLDER'], doc.filename, as_attachment=True)

if __name__ == '__main__':
    init_db() # สร้างฐานข้อมูลและ User เริ่มต้นอัตโนมัติ
    print("Intranet System is running on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)