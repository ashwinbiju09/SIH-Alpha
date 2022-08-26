from math import e
import secrets
import bcrypt
import hashlib
import hmac
import random

from application import app, db, mail, bcrypt_1
from flask import render_template, redirect, url_for, request, flash, send_from_directory, current_app
from application.models import Infrastructure, User, Form_1, Form_2, Form_3, Form_4,Form_5
from flask_mail import Message
from flask_login import login_required, login_user, logout_user, current_user
from werkzeug.utils import secure_filename
import os

UPLOAD_FOLDER = "E:/SIH v2/application/media/user_documents/"

# APP_URL = 'http://127.0.0.1:5000'

def createFolder(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER + request.form['name'])

ACCESS_FOLDER = "E:/SIH v2/application/media/user_documents/"

    
#Home route
@app.route("/")
@app.route("/home")
def home():
    return render_template('index.html')


#Register route
@app.route("/register", methods=['POST','GET'])
def register():
    if request.method == 'POST' :

        #Data from form stored in Database
        name = request.form['name']
        email = request.form['email']

        if email:
            verify(email)

        password = request.form['password']
        phone = request.form['phone']
        role = request.form['role']

        if role == 'Proponent':
            createFolder(UPLOAD_FOLDER)

        if role == 'Tech':
            tech_notification(name,email)

        state = request.form['state']
        city = request.form['city']
        org_name = request.form['org_name']
        aadhar = request.form['aadhar']

        #Hasing Password
        hashed_pwd = bcrypt_1.generate_password_hash(password).decode('utf-8')

        # PEPPER = "QAZ@WWSX1edc647hdffhfhGD977&jjshdhjJG@@3"

        salt = bcrypt.gensalt()

        # peppered_password = hmac.new(PEPPER.encode("utf-8"),password.encode("utf-8"), hashlib.sha256).hexdigest()
        # salted_peppered_password = bcrypt.hashpw(peppered_password.encode("utf-8"), salt)
        # hashed_pwd = salted_peppered_password.decode("utf-8")

        #Storing in DB
        user = User(name=name, email=email, password=hashed_pwd, phone=phone, role=role, state=state, city=city, org_name=org_name,aadhar=aadhar)
        # verification(user)
        db.session.add(user)
        db.session.commit()

        # return redirect(url_for('verification'))
        return redirect(url_for('verification'))
    return render_template('register.html')

def tech_notification(name,email):
    msg = Message('Nomination for Appraisal Committee', sender='20eucs018@skcet.ac.in', recipients=['khelhindustan@gmail.com'])
    msg.html = f''' Greetings !  
    {name} : {email} has registered for the the appraisal and vetting committee. User awaits ministry approval 
    Thank You
    '''
    mail.send(msg)



otp = random.randint(000000,999999)

@app.route('/verify')
def verify(email):
    msg=Message(subject='OTP Verification',sender='20eucs018@skcet.ac.in',recipients=[email])
    msg.body=str(otp)
    mail.send(msg)


@app.route('/verification',methods=["POST","GET"])
def verification():
    print("Hello")
    if request.method == "POST":
        user_otp = request.form['user_otp']
        print(user_otp)
        if otp == int(user_otp) :
            # db.session.add(user)
            # db.session.commit()
            pass
        return redirect(url_for('login'))

    return render_template('otp.html')


#Login route
@app.route("/login",methods=['POST','GET'])
def login():

    if request.method == 'POST' :
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt_1.check_password_hash(user.password, password=password):
            if user.role == "Proponent":
                login_user(user)
                return redirect(url_for('proponent'))
            elif user.role == "Tech" and user.permission == True:
                login_user(user)
                return redirect(url_for('committee'))
            elif user.role == "Admin":
                login_user(user)
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('login'))

    return render_template('login.html')


#Logout routes
@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', sender='noreply@khelhindustan.com', recipients=[user.email])
    msg.html = f''' To reset your password go to the following link : <a href="{ current_app.config['APP_URL'] }{ url_for('reset_token', token=token, external=True) }"> Click here </a> '''
    mail.send(msg)

#password routes
@app.route('/reset_request',methods=['POST','GET'])
def reset_request():
    if request.method == "POST":
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        send_reset_email(user)
        return redirect(url_for('login'))
    return render_template('forgot.html')


@app.route('/reset_token/<token>',methods=['POST','GET'])
def reset_token(token):

    user = User.verify_reset_token(token)

    if request.method == 'GET' :
    #     password = request.form['password']

    #         #Hasing Password
    #     hashed_pwd = bcrypt.generate_password_hash(password).decode('utf-8')
    #     user.password = hashed_pwd
    #     db.session.commit()
        return redirect(url_for('login'))

    return render_template('reset.html')

#User routes based on role
@app.route("/proponent")
@login_required
def proponent():
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    return render_template('/proponent/profile.html')


@app.route("/committee")
@login_required
def committee():
    if not current_user.role == "Tech":
        return redirect(url_for('error'))
    return render_template('/committee/profile.html')

@app.route("/admin")
@login_required
def admin():
    if not current_user.role == "Admin":
        return redirect(url_for('error'))
    return render_template('/admin/profile.html')

#Error routes
@app.route("/error")
def error():
    return render_template('/errors/403.html')


#Proponent routes
@app.route("/application",methods=['POST','GET'])
@login_required
def application():
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    if request.method == 'POST' :
        return redirect(url_for('form_1'))
    return render_template('/proponent/terms.html')


@app.route("/<int:no>/existing_applications",methods=['POST','GET'])
@login_required
def existing_applications(no):
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    if request.method == "POST":
        return redirect(url_for('dpr/<int:id>'))
    allq = Form_2.query.filter_by(user_id=no)
    return render_template('/proponent/existing_applications.html',allq=allq)

@app.route("/status")
@login_required
def status(id):
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    p = Form_1.query.filter_by(id=id).first()
    return render_template('/proponent/status.html',p=p)


@app.route("/notifications")
@login_required
def notifications():
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    return render_template('/proponent/notifications.html')

@app.route("/dpr/<int:id>",methods=['POST','GET'])
@login_required
def dpr(id):
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))

    p = Form_1.query.filter_by(id=id).first()
    q = Form_2.query.filter_by(id=id).first()
    r = Form_3.query.filter_by(id=id).first()
    s = Form_4.query.filter_by(id=id).first()
    t = Form_5.query.filter_by(id=id).first()

    return render_template('/proponent/dpr.html' , p=p, q=q, r=r, s=s, t=t)


#Form routes
@app.route("/form_1",methods=['POST','GET'])
@login_required
def form_1():
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    if request.method == 'POST' :

        #Form input
        name = request.form['name']
        email = request.form['email']
        add1 = request.form['add1']
        add2 = request.form['add2']
        phone = request.form['phone']
        state = request.form['state']
        pincode = request.form['pincode']

        #DB commits
        form_1 = Form_1(name=name, email=email, add1=add1, add2=add2, phone=phone, state=state, pincode=pincode)
        db.session.add(form_1)
        db.session.commit()
        return redirect(url_for('form_2'))
    f1 = Form_1.query.all()
    print(f1)
    return render_template('/proponent/form_1.html',f1=f1)


@app.route("/form_2",methods=['POST','GET'])
@login_required
def form_2():
    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    if request.method == 'POST' :

        #Form input
        name = request.form['name']
        add1 = request.form['add1']
        add2 = request.form['add2']
        mot = request.form['mot']
        mot_name = request.form['mot_name']
        mot_add1 = request.form['mot_add1']
        mot_add2 = request.form['mot_add2']
        distance = request.form['distance']
        area = request.form['area']
        cop = request.form['cop']

        type = request.form['type']
        if(type == "Others"):
          other_type = request.form['other_type']
        else:
          other_type = "none"

        ownership = request.form['ownership']
        availability = request.form['availability']
        utilities = ', '.join(request.form.getlist('utilities'))

        category = request.form['category']
        if(type == "Others"):
          other_cat = request.form['other_cat']
        else:
          other_cat = "none"

        ancillary = request.form['ancillary']
        cost = request.form['cost']
        share = request.form['share']

        #Snippet to input file and store in local directory
        land_proof = request.files['land_proof']
        land_proof_name = "{}_land_proof.pdf".format(current_user.id)
        land_proof.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(land_proof_name)))
        land_proof_rename = "{}_{}_land_proof.pdf".format(current_user.id,secrets.token_hex(16))

        land_certificate = request.files['land_certificate']
        land_certificate_name = "{}_certifiacte.pdf".format(current_user.id)
        land_certificate.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(land_certificate_name)))
        land_certificate_rename = "{}_{}_land_certificate.pdf".format(current_user.id,secrets.token_hex(16))


        boq = request.files['boq']
        boq_name = "{}_boq.pdf".format(current_user.id)
        boq.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(boq_name)))
        boq_rename = "{}_{}_boq.pdf".format(current_user.id,secrets.token_hex(16))



        difference = request.files['difference']
        difference_name = "{}_difference.pdf".format(current_user.id)
        difference.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(difference_name)))
        difference_rename = "{}_{}_difference.pdf".format(current_user.id,secrets.token_hex(16))



        milestones = request.files['milestones']
        milestones_name = "{}_milestones.pdf".format(current_user.id)
        milestones.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(milestones_name)))
        milestones_rename = "{}_{}_milestones.pdf".format(current_user.id,secrets.token_hex(16))



        #DB commits
        form_2 = Form_2(name=name, add1=add1, add2=add2, mot=mot, mot_name=mot_name, mot_add1=mot_add1, mot_add2=mot_add2, distance=distance, area=area, 
        cop=cop, type=type, other_type=other_type, ownership=ownership, availability=availability, utilities=utilities, category=category, other_cat=other_cat, 
        ancillary=ancillary, cost=cost, share=share, user_id=current_user.id,land_proof=land_proof_rename, land_certificate=land_certificate_rename, boq=boq_rename, difference=difference_rename, milestones=milestones_rename )
        db.session.add(form_2)
        db.session.commit()
        return redirect(url_for('form_3'))
    f2 = Form_2.query.all()
    return render_template('/proponent/form_2.html',f2=f2)

@app.route("/form_3",methods=['POST','GET'])
@login_required
def form_3():


    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    if request.method == 'POST' :

        #Form input
        inc = request.form['inc']
        asi =  ', '.join(request.form.getlist('asi'))
        noc = request.form['noc']
        nop = request.form['nop']
        ub = request.form['ub']


        #Snippet to input file and store in local directory
        scope = request.files['scope']
        scope_name = "{}_scope.pdf".format(current_user.id)
        scope.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(scope_name)))
        scope_rename = "{}_{}_scope.pdf".format(current_user.id,secrets.token_hex(16))


        schematic_plan = request.files['schematic_plan']
        schematic_plan_name = "{}_schematic_plan.pdf".format(current_user.id)
        schematic_plan.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(schematic_plan_name)))
        schematic_plan_rename = "{}_{}_scope.pdf".format(current_user.id,secrets.token_hex(16))


        proposed_method = request.files['proposed_method']
        proposed_method_name = "{}_proposed_method.pdf".format(current_user.id)
        proposed_method.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(proposed_method_name)))
        proposed_method_rename = "{}_{}_scope.pdf".format(current_user.id,secrets.token_hex(16))

        fastrack = request.files['fastrack']
        fastrack_name = "{}_fastrack.pdf".format(current_user.id)
        fastrack.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(fastrack_name)))
        fastrack_rename = "{}_{}_scope.pdf".format(current_user.id,secrets.token_hex(16))


        utilization_plan = request.files['utilization_plan']
        utilization_plan_name = "{}_utilization_plan.pdf".format(current_user.id)
        utilization_plan.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(utilization_plan_name)))
        utilization_plan_rename = "{}_{}_scope.pdf".format(current_user.id,secrets.token_hex(16))


        economic_plan = request.files['economic_impact']
        economic_plan_name = "{}_economic_plan.pdf".format(current_user.id)
        economic_plan.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(economic_plan_name)))
        economic_plan_rename = "{}_{}_scope.pdf".format(current_user.id,secrets.token_hex(16))


        integration = request.files['integration']
        integration_name = "{}_integration.pdf".format(current_user.id)
        integration.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(integration_name)))
        integration_rename = "{}_{}_scope.pdf".format(current_user.id,secrets.token_hex(16))


        #DB commits
        form_3 = Form_3(inc=inc, asi=asi, noc=noc, nop=nop, ub=ub, scope=scope_rename, schematic_plan=schematic_plan_rename, proposed_method=proposed_method_rename, fastrack=fastrack_rename, utilization_plan=utilization_plan_rename, economic_plan=economic_plan_rename, integration=integration_rename, )
        db.session.add(form_3)
        db.session.commit()
        return redirect(url_for('form_4'))
    f3 = Form_3.query.all()
    return render_template('/proponent/form_3.html', f3=f3)

@app.route("/form_4",methods=['POST','GET'])
@login_required
def form_4():

    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    if request.method == 'POST' :

        #Form input
        nd = request.form['nd']
        demand = request.form['demand']
        pg = request.form['pg']
        apo = request.form['apo']

        #Snippet to input file and store in local directory
        need = request.files['need']
        need_name = "{}_need.pdf".format(current_user.id)
        need.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(need_name)))
        need_rename = "{}_{}_scope.pdf".format(current_user.id,secrets.token_hex(16))


        excellence = request.files['excellence']
        excellence_name = "{}_excellence.pdf".format(current_user.id)
        excellence.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(excellence_name)))
        excellence_rename = "{}_{}_scope.pdf".format(current_user.id,secrets.token_hex(16))


        estimation = request.files['estimation']
        estimation_name = "{}_estimation.pdf".format(current_user.id)
        estimation.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(estimation_name)))
        estimation_rename = "{}_{}_scope.pdf".format(current_user.id,secrets.token_hex(16))


        benefits = request.files['benefits']
        benefits_name = "{}_benefits.pdf".format(current_user.id)
        benefits.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(benefits_name)))
        benefits_rename = "{}_{}_scope.pdf".format(current_user.id,secrets.token_hex(16))


        equity = request.files['equity']
        equity_name = "{}_equity.pdf".format(current_user.id)
        equity.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(equity_name)))
        equity_rename = "{}_{}_scope.pdf".format(current_user.id,secrets.token_hex(16))


        #DB commits
        form_4 = Form_4(nd=nd, demand=demand, pg=pg, apo=apo, need=need_rename, excellence=excellence_rename, estimation=estimation_rename, equity=equity_rename,benefits=benefits_rename)
        db.session.add(form_4)
        db.session.commit()

        return redirect(url_for('form_5'))
    f4 = Form_4.query.all()
    return render_template('/proponent/form_4.html',f4=f4)

@app.route("/form_5",methods=['POST','GET'])
@login_required
def form_5():

    f2 = Form_2.query.all()

    if not current_user.role == "Proponent":
        return redirect(url_for('error'))
    if request.method == 'POST' :

        #Form input
        prev = request.form['prev']
        od = request.form['od']
        comp = request.form['comp']

        #Snippet to input file and store in local directory
        maintanence = request.files['maintanence']
        maintanence_name = "{}_maintanence.pdf".format(current_user.id)
        maintanence.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(maintanence_name)))
        maintanence_rename = "{}_{}_scope.pdf".format(current_user.id,secrets.token_hex(16))


        design = request.files['design']
        design_name = "{}_design.pdf".format(current_user.id)
        design.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(design_name)))
        design_rename = "{}_{}_scope.pdf".format(current_user.id,secrets.token_hex(16))


        u_certificate = request.files['u_certificate']
        u_certificate_name = "{}_u_certificate.pdf".format(current_user.id)
        u_certificate.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(u_certificate_name)))
        u_certificate_rename = "{}_{}_scope.pdf".format(current_user.id,secrets.token_hex(16))


        details = request.files['details']
        details_name = "{}_details.pdf".format(current_user.id)
        details.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(details_name)))
        details_rename = "{}_{}_scope.pdf".format(current_user.id,secrets.token_hex(16))


        proof = request.files['proof']
        proof_name = "{}_proof.pdf".format(current_user.id)
        proof.save(os.path.join('E:/SIH v2/application/media/user_documents/'+ current_user.name , secure_filename(proof_name)))
        proof_rename = "{}_{}_scope.pdf".format(current_user.id,secrets.token_hex(16))


        #DB commits
        form_5 = Form_5(prev=prev, od=od, comp=comp, maintanence=maintanence_rename, design=design_rename, u_certificate=u_certificate_rename, details=details_rename, proof=proof_rename)
        db.session.add(form_5)
        db.session.commit()
        return redirect("/"+str(current_user.id)+"/existing_applications")
    f5 = Form_5.query.all()
    return render_template('/proponent/form_5.html',f5=f5)




#tech_committee routes
@app.route("/projects",methods=['POST','GET'])
@login_required
def projects():
    if not current_user.role == "Tech":
         return redirect(url_for('error'))
    
    p = Form_2.query.filter_by(committee_approval=0).all()

    if request.method == "POST":
        req = request.form['method']
        id = request.form['id']
        project  = Form_2.query.filter_by(id=id).first()
        if req == '1':
            if project:
                setattr(project,'committee_approval',1)
        if req == '2':
            if project:
                setattr(project,'committee_approval',2)
        db.session.commit()
    return render_template('/committee/projects.html', p=p)


@app.route("/cdpr/<int:id>",methods=['POST','GET'])
@login_required
def cdpr(id):
        if not current_user.role == "Tech":
            return redirect(url_for('error'))

        p = Form_1.query.filter_by(id=id).first()
        q = Form_2.query.filter_by(id=id).first()
        r = Form_3.query.filter_by(id=id).first()
        s = Form_4.query.filter_by(id=id).first()
        t = Form_5.query.filter_by(id=id).first()

        return render_template("/committee/dpr.html",p=p,q=q,r=r,s=s,t=t)
        

@app.route("/cdpr_marks/<int:id>",methods=['POST','GET'])
@login_required
def cdpr_marks(id):
        if not current_user.role == "Tech":
            return redirect(url_for('error'))
            
        if request.method == 'POST':
            p = Form_1.query.filter_by(id=id).first()
            q = Form_2.query.filter_by(id=id).first()
            r = Form_3.query.filter_by(id=id).first()
            s = Form_4.query.filter_by(id=id).first()
            if request.form['qm1']:
                q.m1 = request.form['qm1']
            if request.form['qm2']:
                q.m2 = request.form['qm2']
            if request.form['qm3']:
                q.m3 = request.form['qm3']
            if request.form['qm4']:
                q.m4 = request.form['qm4']
            if request.form['qm5']:
                q.m5 = request.form['qm5']
            if request.form['qm6']:
                q.m6 = request.form['qm6']
            if request.form['qm7']:
                q.m7 = request.form['qm7']
            if request.form['qm8']:
                q.m8 = request.form['qm8']
            if request.form['qm9']:
                q.m9 = request.form['qm9']

            if request.form['rm1']:
                r.m1 = request.form['rm1']
            if request.form['rm2']:
                r.m2 = request.form['rm2']
            if request.form['rm3']:
                r.m3 = request.form['rm3']
            if request.form['rm4']:
                r.m4 = request.form['rm4']
            if request.form['rm5']:
                r.m5 = request.form['rm5']
            if request.form['rm6']:
                r.m6 = request.form['rm6']
            if request.form['rm7']:
                r.m7 = request.form['rm7']
            if request.form['rm8']:
                r.m8 = request.form['rm8']
            if request.form['rm9']:
                r.m9 = request.form['rm9']
            if request.form['rm10']:
                r.m10 = request.form['rm10']

            if request.form['sm1']:
                s.m1 = request.form['sm1']
            if request.form['sm2']:
                s.m2 = request.form['sm2']
            if request.form['sm3']:
                s.m3 = request.form['sm3']
            if request.form['sm4']:
                s.m4 = request.form['sm4']
            if request.form['sm5']:
                s.m5 = request.form['sm5']
            if request.form['sm6']:
                s.m6 = request.form['sm6']
            if request.form['sm7']:
                s.m7 = request.form['sm7']
            if request.form['sm8']:
                s.m8 = request.form['sm8']

            q.tot = int(float(q.m1)+float(q.m2)+float(q.m3)+float(q.m4)+float(q.m5)+float(q.m6)+float(q.m7)+float(q.m8)+float(q.m9))
            r.tot = int(float(r.m1)+float(r.m2)+float(r.m3)+float(r.m4)+float(r.m5)+float(r.m6)+float(r.m7)+float(r.m8)+float(r.m9)+float(r.m10))
            s.tot = int(float(s.m1)+float(s.m2)+float(s.m3)+float(s.m4)+float(s.m5)+float(s.m6)+float(s.m7)+float(s.m8))
            q.total = q.tot+r.tot+s.tot


            db.session.add(q)
            db.session.add(r)
            db.session.add(s)
            db.session.commit()

            t = Form_5.query.filter_by(id=id).first()
            return redirect(url_for('cdpr',id=id))

        p = Form_1.query.filter_by(id=id).first()
        q = Form_2.query.filter_by(id=id).first()
        r = Form_3.query.filter_by(id=id).first()
        s = Form_4.query.filter_by(id=id).first()
        t = Form_5.query.filter_by(id=id).first()
        return render_template('committee/dpr_marks.html',p=p,q=q,r=r,s=s,t=t)

@app.route('/filter_projects/<string:state>', methods=['GET','POST'])
@login_required
def fil_pro(state):
    p = Form_2.query.filter_by(add2=state).all()
    return render_template('/committee/filter_projects.html',p=p)

@app.route('/filter_projects/approved/<string:state>', methods=['GET','POST'])
@login_required
def fil_app_pro(state):
    if not current_user.role == "Tech":
         return redirect(url_for('error'))
    p = Form_2.query.filter_by(add2=state, committee_approval=1).all()
    return render_template('/committee/approved_filter_projects.html',p=p)

@app.route('/filter_projects/rejected/<string:state>', methods=['GET','POST'])
@login_required
def fil_rej_pro(state):
    if not current_user.role == "Tech":
         return redirect(url_for('error'))
    p = Form_2.query.filter_by(add2=state, committee_approval=2).all()
    return render_template('/committee/rejected_filter_projects.html',p=p)

@app.route("/sanctioned_projects",methods=['POST','GET'])
@login_required
def sanctioned_projects():
        if not current_user.role == "Tech":
            return redirect(url_for('error'))
        p=Form_2.query.filter_by(committee_approval=1).all()
        return render_template("/committee/sanctioned.html",p=p)

@app.route("/rejected_projects",methods=['POST','GET'])
@login_required
def rejected_projects():
        if not current_user.role == "Tech":
            return redirect(url_for('error'))
        p=Form_2.query.filter_by(committee_approval=2).all()
        return render_template("/committee/rejected.html",p=p)


#admin routes
@app.route("/approval",methods=['POST','GET'])
@login_required
def approval():
    if not current_user.role == "Admin":
         return redirect(url_for('error'))

    users = User.query.filter_by(role='Tech').all()

    if request.method == "POST":
            permission = request.form['permission']
            id = request.form['user_id']
            email = request.form['email']
            user = User.query.get(id)
            if user :
                value = permission == '1' if True else False
                setattr(user,'permission',value)
            if permission == '1':
                approval_email(email)
            elif permission == '0':
                denied_mail(email)
            db.session.commit()
            return redirect(url_for('approval'))

    return render_template('admin/permission.html',users=users)

def approval_email(email):
    msg = Message('Access Granted', sender='20eucs018@skcet.ac.in', recipients=[email])
    msg.html = f''' Greetings !
    Your application has been approved. You can now sign in with your credentials.
    Thank You !
    '''
    mail.send(msg)

def denied_mail(email):
    msg = Message('Access Denied', sender='20eucs018@skcet.ac.in', recipients=[email])
    msg.html = f''' Greetings !
    Your application has been denied. For further queries contact system admin.
    Thank You !
    '''
    mail.send(msg)


@app.route("/project",methods=['POST','GET'])
@login_required
def admin_projects():
    if not current_user.role == "Admin":
         return redirect(url_for('error'))
    
    p = Form_2.query.filter_by(committee_approval=1).all()

    if request.method == "POST":
        req = request.form['method']

        if req == "1":
            return redirect(url_for('sanctioned_projects'))
        if req == "2":
            return redirect(url_for('rejected_projects'))
    return render_template('/admin/projects.html', p=p)

@app.route("/approved",methods=['POST','GET'])
@login_required
def admin_approved_project():
    if not current_user.role == "Admin":
         return redirect(url_for('error'))
    
    p = Form_2.query.filter_by(ministry_approval=1).all()

    return render_template('/admin/approved.html', p=p)

@app.route("/rejectedpro",methods=['POST','GET'])
@login_required
def admin_rejected_project():
    if not current_user.role == "Admin":
         return redirect(url_for('error'))
    
    p = Form_2.query.filter_by(ministry_approval=2).all()

    return render_template('/admin/rejected.html', p=p)

@app.route("/dpr_admin/<int:id>",methods=['POST','GET'])
@login_required
def dpr_admin(id):
        if not current_user.role == "Admin":
            return redirect(url_for('error'))

        p = Form_1.query.filter_by(id=id).first()
        q = Form_2.query.filter_by(id=id).first()
        r = Form_3.query.filter_by(id=id).first()
        s = Form_4.query.filter_by(id=id).first()
        t = Form_5.query.filter_by(id=id).first()

        return render_template("/admin/dpr.html",p=p,q=q,r=r,s=s,t=t)



@app.route('/filter_projects_ad/<string:state>', methods=['GET','POST'])
@login_required
def admin_filter_projects(state):
    if not current_user.role == "Admin":
        return redirect(url_for('error'))
    p = Form_2.query.filter_by(add2=state).all()
    return render_template('/admin/filter_projects.html',p=p)

@app.route('/filter_projects_ad/approved/<string:state>', methods=['GET','POST'])
@login_required
def admin_app(state):
    if not current_user.role == "Admin":
         return redirect(url_for('error'))
    p = Form_2.query.filter_by(add2=state, ministry_approval=1).all()
    return render_template('/admin/filter_app.html',p=p)

@app.route('/filter_projects_ad/rejected/<string:state>', methods=['GET','POST'])
@login_required
def admin_rej(state):
    if not current_user.role == "Admin":
         return redirect(url_for('error'))
    p = Form_2.query.filter_by(add2=state, ministry_approval=2).all()
    return render_template('/admin/filter_rej.html',p=p)

@app.route("/sanctioned_infrastructure")
@login_required
def sanctioned_infrastructure():
    if not current_user.role == "Admin":
        return redirect(url_for('error'))
    
    projects = Infrastructure.query.all()

    return render_template('/admin/infrastructure.html',projects=projects)

#file routes
@app.route("/land_proof",methods=['GET','POST'])
@login_required
def land_proof():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_land_proof.pdf')

@app.route("/land_certificate",methods=['GET','POST'])
@login_required
def land_certificate():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_land_certificate.pdf')

@app.route("/boq",methods=['GET','POST'])
@login_required
def boq():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_boq.pdf')

@app.route("/difference",methods=['GET','POST'])
@login_required
def difference():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_difference.pdf')

@app.route("/milestones",methods=['GET','POST'])
@login_required
def milestones():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_milestones.pdf')

@app.route("/scope",methods=['GET','POST'])
@login_required
def scope():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_scope.pdf')

@app.route("/schematic_plan",methods=['GET','POST'])
@login_required
def schematic_plan():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_schematic_plan.pdf')

@app.route("/proposed_method",methods=['GET','POST'])
@login_required
def proposed_method():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_proposed_method.pdf')

@app.route("/fastrack",methods=['GET','POST'])
@login_required
def fastrack():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_fastrack.pdf')

@app.route("/utilization_plan",methods=['GET','POST'])
@login_required
def utilization_plan():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_utilization_plan.pdf')

@app.route("/economic_impact",methods=['GET','POST'])
@login_required
def economic_impact():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_economic_impact.pdf')

@app.route("/integration",methods=['GET','POST'])
@login_required
def integration():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_integration.pdf')

@app.route("/need",methods=['GET','POST'])
@login_required
def need():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_need.pdf')

@app.route("/excellence",methods=['GET','POST'])
@login_required
def excellence():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_excellence.pdf')

@app.route("/estimation",methods=['GET','POST'])
@login_required
def estimation():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_estimation.pdf')

@app.route("/benefits",methods=['GET','POST'])
@login_required
def benefits():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_benefits.pdf')

@app.route("/equity",methods=['GET','POST'])
@login_required
def equity():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_equity.pdf')

@app.route("/maintanence",methods=['GET','POST'])
@login_required
def maintanence():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_maintanence.pdf')

@app.route("/design",methods=['GET','POST'])
@login_required
def design():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_design.pdf')

@app.route("/u_certificate",methods=['GET','POST'])
@login_required
def u_certificate():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_u_certificate.pdf')

@app.route("/details",methods=['GET','POST'])
@login_required
def details():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_details.pdf')

@app.route("/proof",methods=['GET','POST'])
@login_required
def proof():

    path = "E:/SIH v2/application/media/user_documents/" + current_user.name + "/"
    return send_from_directory(path, str(current_user.id)+'_proof.pdf')