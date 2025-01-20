from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Creates a manager group and give crud permissions for normal users to it'

    def handle(self, *args, **options):
        from django.contrib.auth.models import Group

        group, created = Group.objects.get_or_create(name='manager')
        if created:
            self.stdout.write(self.style.SUCCESS('Manager group created'))
        else:
            self.stdout.write(self.style.SUCCESS('Manager group already exists'))
