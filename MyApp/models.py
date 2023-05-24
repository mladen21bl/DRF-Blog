from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    ip_addresses = models.TextField(blank=True)

    def add_ip_address(self, ip_address):
        ip_addresses_list = self.ip_addresses.split(',') if self.ip_addresses else []
        if ip_address not in ip_addresses_list:
            ip_addresses_list.append(ip_address)
            self.ip_addresses = ','.join(ip_addresses_list)
            self.save()

    def verify_ip_address(self, token):
        if default_token_generator.check_token(self.user, token):
            return True
        return False

    def add_verified_ip_address(self, ip_address):
        if self.verify_ip_address(ip_address):
            self.add_ip_address(ip_address)
            return True
        return False

    def get_ip_addresses(self):
        return self.ip_addresses.split(',') if self.ip_addresses else []
