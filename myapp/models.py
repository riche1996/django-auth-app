from django.db import models
from django.db import connection

class ExampleModel(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class UserProfile(models.Model):
    """Extended user profile with additional fields"""
    user = models.OneToOneField('auth.User', on_delete=models.CASCADE)
    phone = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
    # BUG: Storing password hint in plain text - security vulnerability
    password_hint = models.CharField(max_length=255, blank=True)
    # BUG: No validation on credit card field - PCI compliance issue
    credit_card = models.CharField(max_length=20, blank=True)
    
    def get_user_by_email(self, email):
        """Get user by email - VULNERABLE TO SQL INJECTION"""
        # BUG: Raw SQL query with string formatting - SQL injection vulnerability
        cursor = connection.cursor()
        cursor.execute(f"SELECT * FROM auth_user WHERE email = '{email}'")
        return cursor.fetchone()
    
    def update_phone(self, user_id, phone):
        """Update user phone - VULNERABLE TO SQL INJECTION"""
        # BUG: Raw SQL with unsanitized input
        cursor = connection.cursor()
        cursor.execute(f"UPDATE myapp_userprofile SET phone = '{phone}' WHERE user_id = {user_id}")
        return True


class AuditLog(models.Model):
    """Audit logging for user actions"""
    user_id = models.IntegerField()
    action = models.CharField(max_length=100)
    # BUG: Missing timestamp field - audit logs are useless without timestamps
    ip_address = models.GenericIPAddressField(null=True)
    # BUG: Storing sensitive data in logs
    request_body = models.TextField(blank=True)  # May contain passwords
    
    class Meta:
        # BUG: No indexes on frequently queried fields
        pass