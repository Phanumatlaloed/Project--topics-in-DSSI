from django import forms
from .models import Member, CommunityGroup, GroupPost, UserProfile
from .models import Post
from django.core.exceptions import ValidationError

class MemberForm(forms.ModelForm):
    class Meta:
        model = Member
        fields = ['gender', 'date_of_birth']  # ใช้ฟิลด์ที่มีใน Member เท่านั้น

from django.contrib.auth.models import User

class UserForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'password']
class AccountEditForm(forms.ModelForm):
    class Meta:
        model = Member
        fields = ['gender', 'date_of_birth']
        widgets = {
            'date_of_birth': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'gender': forms.Select(attrs={'class': 'form-control'}),
        }

class PasswordChangeForm(forms.Form):
    current_password = forms.CharField(
        label="Current Password",
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
    )
    new_password = forms.CharField(
        label="New Password",
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
    )
    confirm_new_password = forms.CharField(
        label="Confirm New Password",
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_current_password(self):
        current_password = self.cleaned_data.get("current_password")
        if not self.user.check_password(current_password):
            raise forms.ValidationError("The current password is incorrect.")
        return current_password

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password")
        confirm_new_password = cleaned_data.get("confirm_new_password")

        if new_password != confirm_new_password:
            raise forms.ValidationError("The new passwords do not match.")
        return cleaned_data
    
class CommunityGroupForm(forms.ModelForm):
    class Meta:
        model = CommunityGroup
        fields = ['name', 'description', 'rules', 'image']

class GroupPostForm(forms.ModelForm):
    class Meta:
        model = GroupPost
        fields = ['content', 'image', 'video']
class AccountEditForm(forms.ModelForm):
    class Meta:
        model = Member
        fields = ['gender', 'date_of_birth', 'profile_picture'] #เพิ่ม profile_picture ใน fields
        widgets = {
            'date_of_birth': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'gender': forms.Select(attrs={'class': 'form-control'}),
        }


class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['profile_picture'] #เพิ่มใหม่ไว้ล่างสุด