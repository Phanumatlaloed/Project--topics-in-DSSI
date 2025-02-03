from django import forms
from .models import Member, CommunityGroup, GroupPost, UserProfile
from .models import Post, Seller, Product, CustomUser, Post, PostMedia
from django.core.exceptions import ValidationError
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import get_user_model

User = get_user_model()  # ✅ ใช้ CustomUser

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

class ProductForm(forms.ModelForm):
    class Meta:
        model = Product
        fields = ['name', 'description', 'price', 'stock', 'image']

from django import forms
from .models import Seller, CustomUser
class SellerForm(forms.ModelForm):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'class': 'form-control'}),
        error_messages={'required': 'กรุณากรอกอีเมล'}
    )

    class Meta:
        model = Seller
        fields = ['store_name', 'email', 'store_image', 'contact_info']
        widgets = {
            'store_name': forms.TextInput(attrs={"class": "form-control"}),
            'contact_info': forms.Textarea(attrs={"class": "form-control"}),
        }




class CustomUserForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ['username', 'password1', 'password2']
        widgets = {
            'username': forms.TextInput(attrs={"class": "form-control"}),
            'password1': forms.PasswordInput(attrs={"class": "form-control"}),
            'password2': forms.PasswordInput(attrs={"class": "form-control"}),
        }


class SellerUpdateForm(forms.ModelForm):
    class Meta:
        model = Seller
        fields = ['store_name', 'store_image', 'contact_info']
class CustomUserForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = ['username', 'password1', 'password2']  # ใช้แค่ username และ email

class UserEditForm(forms.ModelForm):
    class Meta:
        model = CustomUser  # ✅ ใช้ CustomUser แทน User
        fields = ['username', 'first_name', 'last_name', 'email']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control'}),
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
        }
class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'class': 'form-control'}),
        error_messages={'required': 'กรุณากรอกอีเมล'}
    )

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password1', 'password2']


from django import forms
from .models import Post, PostMedia

class EditPostForm(forms.ModelForm):
    """ ฟอร์มแก้ไขโพสต์ (เฉพาะข้อความ) """
    class Meta:
        model = Post
        fields = ['content']

