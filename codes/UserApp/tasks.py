from config.celery_base import app
from .models import CustomUser


@app.task(queue='tasks')
def unblock_user(user_id):
    user = CustomUser.get_or_none(id=user_id)
    user.is_active = True
    user.save()


@app.task(queue='tasks')
def send_sms(phone_number, message):
    print(f'message: ({message}) sent to {phone_number}')
