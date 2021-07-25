'''from email.message import EmailMessage'''
from django.core import mail
from django.core.mail import send_mail, EmailMessage
from django.http import HttpResponse

from django.shortcuts import render, redirect, HttpResponseRedirect
from django.forms import inlineformset_factory
from django.contrib.auth.forms import UserCreationForm
from django.template.context_processors import request
from django.contrib.auth import authenticate, login, logout
from .forms import *

from django.contrib.auth.decorators import login_required
from .models import Member
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib import messages
from django.db.models import Q
import math, random



EMAIL=''
def home(request):
    return render(request,'account/home.html')
def login(request):
    if request.method=='POST':
        Email=request.POST['e-mail']
        Password=request.POST['password']
        print(Email)
        try:
            validate_email(Email)
            member=Member.objects.all().filter(Q(email=Email))

            if (member):
               print(member[0],"xxx",Member)
               if(member[0])==Password:
                  print ('yes')
                  return redirect('/student_details/')
               else:
                  messages.error(request, 'Incorrect Password')
                  return render(request, 'account/login.html')
            else:
               print('no')
               messages.error(request,'Email not registered')
               return render(request, 'account/login.html')
        except ValidationError as error:
            print(error)
            messages.error(request, "messages.error")
            return render(request, 'account/login.html')

    else:
        return render(request,'account/login.html')

def register(request):
    '''form = CreateUserForm()
    if request.method == 'POST':
        form = CreateUserForm(request.POST)
        if form.is_valid():
            form.save()
            user = form.cleaned_data.get('studentname')
            messages.success(request, 'Account was created for ' + user)
            return redirect('/student_details/')
        else:
            messages.error(request,form.errors)
            return render(request, 'account/register.html')
    else:
        return render(request, 'account/register.html')'''
    if request.method == 'POST':
        field = Member(studentname=request.POST['Name'], password=request.POST['Password'],
                      cnfrmpassword=request.POST['Re-password'], email=request.POST['E-mail'],
                      phone=request.POST['Phone no.'])
        Email=request.POST['E-mail']
        try:
            validate_email(Email)
            if request.POST['Password'] != request.POST['Re-password']:
                messages.error(request, 'passwords did not match')
                
            else:
                if (Member.objects.filter(Q(email=Email))):
                    print(Member.objects.filter(Q(email=Email)))
                    messages.error(request,'E-mail already exist')
                else:
                    field.save()
                    return redirect('/student_details/')
        except ValidationError:
            messages.error(request,'enter valid email')
        return render(request, 'account/register.html')

    else:

        return render(request, 'account/register.html')

def student_details(request):
    return render(request,'account/student_details.html')
'''def reset_password(request):
    return render(request,'account/reset_password.html')'''
def reset_password(request):
    if request.method=='POST':
       EMAIL=request.POST.get('e-mail')
       try:
           validate_email(EMAIL)
           '''if (Member.objects.filter(Q(email=EMAIL))):
               send_mail('Subject here', 'Here is the message.', 'sems.maa.school1@example.com',
                         ['soumyashree.guddi@gmail.com'], fail_silently=False)
               print("mail sent")
           else:
               messages.error(request, 'Email you have entered is not registered!')
               return render(request, 'account/registration/password_reset_form.html')'''

       except:
           messages.error(request, 'Enter valid email')
           return render(request, 'account/registration/password_reset_form.html')

       '''mail = EmailMessage('Mail test', 'this is a test', to=['soumyashree.guddi@gmail.com'])
       mail.send()'''
       o=generateOTP()
       try:
           htmlgen = '<p>Your OTP is :<strong>' + str(o) + '</strong></p> <p>Expires in :<strong> 10 minutes</strong>'
           send_mail('OTP Request', 'your otp is:' + str(o), 'sems.maa.school1@example.com',
                     ['soumyashree.guddi@gmail.com'],
                     fail_silently=False, html_message=htmlgen)

       except:
           print(HttpResponse('Invalid header found.'))
           print('exception')

       return redirect('/reset_password/otp_varification/')

    return  render(request,'account/registration/password_reset_form.html')
def otp_varification(request):
    if request.method=='POST':

        return redirect('/login/')
    else:
        print("I am here")
        return  render(request,'account/registration/otp_varification.html')



'''@views.route('/background_process_test')
def resend_Password():
    o=generateOTP()
    htmlgen = '<p>Your OTP is <strong>o</strong></p>'
    send_mail('OTP Request', o, 'sems.maa.school1@example.com', ['soumyashree.guddi@gmail.com'], fail_silently=False,
              html_message=htmlgen)
    print("mail sent")'''
def fun(request):
    print("hi")
    send_request()
    return render(request, 'account/registration/otp_varification.html')

def generateOTP():
    digits = "0123456789"
    OTP = ""
    for i in range(4):
        OTP += digits[math.floor(random.random() * 10)]
    return OTP

def send_request():
    o = generateOTP()
    htmlgen = '<p>Your OTP is :<strong>' + str(o) + '</strong></p> <p>Expires in :<strong> 10 minutes</strong>'
    send_mail('OTP Request', 'your otp is:' + str(o), 'sems.maa.school1@example.com', ['soumyashree.guddi@gmail.com'],
              fail_silently=False, html_message=htmlgen)
    print(EMAIL)
    print("mail sent")