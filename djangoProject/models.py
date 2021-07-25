from django.db import models;



class Member(models.Model):
    studentname=models.CharField(max_length=30)
    password=models.CharField(max_length=30)
    cnfrmpassword =models.CharField(max_length=30)
    email=models.EmailField(max_length=30,primary_key=True,unique=True)
    phone=models.IntegerField()

    def __str__(self):
        return self.password
    def get_password(self):
        return self.password
