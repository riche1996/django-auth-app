from django.db import models
from django.contrib.auth.models import User
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
import hashlib

class ExampleModel(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class UserProfile(models.Model):
    """Extended user profile with additional fields"""
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    
    # Phone validation with regex
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$', 
        message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
    )
    phone = models.CharField(validators=[phone_regex], max_length=17, blank=True)
    address = models.TextField(blank=True)
    
    # FIXED: Remove password hint entirely - security best practice
    # password_hint = models.CharField(max_length=255, blank=True)  # REMOVED
    
    # FIXED: Remove credit card storage - use secure payment processor instead
    # credit_card = models.CharField(max_length=20, blank=True)  # REMOVED
    
    # Add secure fields if needed
    profile_verified = models.BooleanField(default=False)
    security_question_hash = models.CharField(max_length=64, blank=True)  # Hashed security answer
    
    def set_security_answer(self, answer):
        """Store hashed security answer instead of password hint"""
        if answer:
            self.security_question_hash = hashlib.sha256(answer.encode()).hexdigest()
    
    def verify_security_answer(self, answer):
        """Verify security answer against hash"""
        if not self.security_question_hash or not answer:
            return False
        return self.security_question_hash == hashlib.sha256(answer.encode()).hexdigest()
    
    def get_user_by_email(self, email):
        """Get user by email - FIXED: Using Django ORM with parameterized queries"""
        try:
            return User.objects.get(email=email)
        except User.DoesNotExist:
            return None
    
    def update_phone(self, user_id, phone):
        """Update user phone - FIXED: Using Django ORM with validation"""
        try:
            profile = UserProfile.objects.get(user_id=user_id)
            profile.phone = phone
            profile.full_clean()  # Validates phone format
            profile.save()
            return True
        except (UserProfile.DoesNotExist, ValidationError):
            return False
    
    def clean(self):
        """Additional validation"""
        super().clean()
        # Add any additional validation logic here
    
    class Meta:
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['phone']),
        ]


class AuditLog(models.Model):
    """Audit logging for user actions"""
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=100)
    
    # FIXED: Added timestamp fields
    created_at = models.DateTimeField(auto_now_add=True)
    
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
    # FIXED: Only store non-sensitive metadata
    endpoint = models.CharField(max_length=255, blank=True)
    user_agent = models.TextField(blank=True)
    status_code = models.IntegerField(null=True, blank=True)
    
    # REMOVED: request_body field to prevent logging sensitive data
    
    class Meta:
        # FIXED: Added indexes for performance
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['action', 'created_at']),
            models.Index(fields=['ip_address', 'created_at']),
            models.Index(fields=['created_at']),
        ]
        ordering = ['-created_at']
    
    def __str__(self):
        username = self.user.username if self.user else 'Anonymous'
        return f"{username} - {self.action} - {self.created_at}"