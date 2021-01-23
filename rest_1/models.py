from django.db import models

# Create your models here.
class new_user(models.Model):
    username = models.CharField(max_length=100, blank=True, default='NA')
    age = models.CharField(max_length=100, blank=True, default='NA')
    phone_number = models.CharField(max_length=100, blank=True, default='1234567890')
    email = models.CharField(max_length=100, blank=True, default='abc@gmail.com')
    password = models.CharField(max_length=100)
    softdelete = models.BooleanField(default=False)
    date = models.DateTimeField(auto_now_add=True)
    # phone_number = PhoneNumberField(null=False, blank=False, unique=True)
    # phone = PhoneNumber.from_string(phone_number=raw_phone, region='RU').as_e164

    class Meta:
        ordering = ['date']
