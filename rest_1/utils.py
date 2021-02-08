# from django.core.mail import EmailMessage
import threading
from django.conf import settings
from django.core.mail import send_mail

class Util:
    @staticmethod
    def sending(data):
        # subject = data['email_subject']
        # message = data['email_body']
        # email_from = settings.EMAIL_HOST_USER
        # recipient_list = [data['to_email']]
        send_mail(data['email_subject'], data['email_body'], settings.EMAIL_HOST_USER, [data['to_email']])

    def send_email(data):
        trigger = threading.Thread(target=Util.sending(data))
        trigger.start()

