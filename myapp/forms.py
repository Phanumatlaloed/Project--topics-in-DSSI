from django import forms
from .models import Member, CommunityGroup, GroupPost, UserProfile
from .models import Post, Seller, Product, CustomUser, Post, PostMedia, ShippingAddress
from django.core.exceptions import ValidationError
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserChangeForm, PasswordChangeForm

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
        fields = ['name', 'description', 'price', 'stock', 'image', 'category']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control'}),
            'price': forms.NumberInput(attrs={'class': 'form-control'}),
            'stock': forms.NumberInput(attrs={'class': 'form-control'}),
            'image': forms.FileInput(attrs={'class': 'form-control'}),
            'category': forms.Select(attrs={'class': 'form-control'}),  # ✅ Dropdown เลือกหมวดหมู่
        }

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
CustomUser = get_user_model()

class SelleruserUpdateForm(UserChangeForm):
    """ ฟอร์มแก้ไขข้อมูลผู้ใช้ (User) """
    class Meta:
        model = CustomUser
        fields = ['username', 'email']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
        }

class SelleruserPasswordUpdateForm(PasswordChangeForm):
    """ ฟอร์มเปลี่ยนรหัสผ่าน (User) """
    old_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'รหัสผ่านเดิม'})
    )
    new_password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'รหัสผ่านใหม่'})
    )
    new_password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'ยืนยันรหัสผ่านใหม่'})
    )

class SellerUpdateForm(forms.ModelForm):
    """ ฟอร์มแก้ไขข้อมูลร้านค้า """
    class Meta:
        model = Seller
        fields = ['store_name', 'contact_info', 'store_image']
        widgets = {
            'store_name': forms.TextInput(attrs={'class': 'form-control'}),
            'contact_info': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
            'store_image': forms.ClearableFileInput(attrs={'class': 'form-control'}),
        }
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

class ShippingAddressForm(forms.ModelForm):
    class Meta:
        model = ShippingAddress
        fields = ['address', 'city', 'postal_code', 'phone_number']  # ✅ เพิ่ม city และ postal_code
        labels = {
            'address': '📍 ที่อยู่จัดส่ง',
            'city': '🏙 เมือง',
            'postal_code': '📮 รหัสไปรษณีย์',
            'phone_number': '📞 เบอร์โทรศัพท์',
        }



from .models import Report

class ReportForm(forms.ModelForm):
    class Meta:
        model = Report
        fields = ['reason', 'description']


class AdminRegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password1', 'password2']

    def save(self, commit=True):
        user = super().save(commit=False)
        user.is_staff = True  # ✅ ให้แอดมินเป็น staff อัตโนมัติ
        if commit:
            user.save()
        return user
    
#class ShippingAddressForm(forms.ModelForm):
   # class Meta:
      #  model = ShippingAddress
      #  fields = ['address', 'phone_number']
      #  labels = {
       #     'address': '📍 ที่อยู่จัดส่ง',
       #     'phone_number': '📞 เบอร์โทรศัพท์',
      #  }

from .models import Report

class ReportForm(forms.ModelForm):
    class Meta:
        model = Report
        fields = ['reason', 'description']


class AdminRegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password1', 'password2']

    def save(self, commit=True):
        user = super().save(commit=False)
        user.is_staff = True  # ✅ ให้แอดมินเป็น staff อัตโนมัติ
        if commit:
            user.save()
        return user

class ShippingAddressForm(forms.ModelForm):
    """ ฟอร์มสำหรับเพิ่ม / แก้ไขที่อยู่จัดส่ง """
    class Meta:
        model = ShippingAddress
        fields = ['address', 'phone_number', 'city', 'postal_code']
        labels = {
            'address': '📍 ที่อยู่',
            'phone_number': '📞 เบอร์โทรศัพท์',
            'city': '🏙 เมือง',
            'postal_code': '📮 รหัสไปรษณีย์',
        }
        widgets = {
            'address': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'กรอกที่อยู่ของคุณ...'}),
            'phone_number': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'เบอร์โทรศัพท์'}),
            'city': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'ชื่อเมือง'}),
            'postal_code': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'รหัสไปรษณีย์'}),
        }
    
    def clean_phone_number(self):
        """ ตรวจสอบหมายเลขโทรศัพท์ให้ถูกต้อง """
        phone_number = self.cleaned_data.get('phone_number')
        if not phone_number.isdigit():
            raise forms.ValidationError("⚠️ เบอร์โทรศัพท์ต้องเป็นตัวเลขเท่านั้น")
        if len(phone_number) < 9 or len(phone_number) > 15:
            raise forms.ValidationError("⚠️ เบอร์โทรศัพท์ต้องมีความยาวระหว่าง 9-15 ตัว")
        return phone_number

    def clean_postal_code(self):
        """ ตรวจสอบรหัสไปรษณีย์ """
        postal_code = self.cleaned_data.get('postal_code')
        if not postal_code.isdigit():
            raise forms.ValidationError("⚠️ รหัสไปรษณีย์ต้องเป็นตัวเลขเท่านั้น")
        if len(postal_code) not in [5, 6]:
            raise forms.ValidationError("⚠️ รหัสไปรษณีย์ต้องมีความยาว 5 หรือ 6 ตัวอักษร")
        return postal_code
    
# ✅ ฟอร์มแก้ไขโปรไฟล์ผู้ใช้ทั่วไป
class UserProfileForm(forms.ModelForm):
    class Meta:
        model = CustomUser  # ✅ ใช้ CustomUser
        fields = ['first_name', 'last_name', 'email']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'ชื่อ'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'นามสกุล'}),
            'email': forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'อีเมล'}),
        }

# ✅ ฟอร์มแก้ไขข้อมูลร้านค้า (สำหรับ Seller)
class SellerUpdateForm(forms.ModelForm):
    """ ฟอร์มแก้ไขข้อมูลร้านค้า """
    class Meta:
        model = Seller
        fields = ("store_name", "store_image", "contact_info", "bank_name", "bank_account_name", "bank_account_number")
        widgets = {
            'store_name': forms.TextInput(attrs={'class': 'form-control'}),
            'contact_info': forms.Textarea(attrs={'class': 'form-control'}),
            'store_image': forms.ClearableFileInput(attrs={'class': 'form-control'}),
            'bank_name': forms.Select(attrs={'class': 'form-control'}),  # ✅ dropdown
            'bank_account_name': forms.TextInput(attrs={'class': 'form-control'}),
            'bank_account_number': forms.TextInput(attrs={'class': 'form-control'}),
        }


from django import forms
from django.contrib.auth.forms import UserChangeForm
from .models import CustomUser, Seller

class CustomUserUpdateForm(UserChangeForm):
    """ ฟอร์มอัปเดตข้อมูลผู้ใช้ (อีเมล, ชื่อ, username) """
    password = None  # ✅ ซ่อนฟิลด์รหัสผ่าน

    class Meta:
        model = CustomUser
        fields = ("username", "email", "first_name", "last_name")

class SellerProfileUpdateForm(forms.ModelForm):
    """ ฟอร์มอัปเดตข้อมูลร้านค้า """
    class Meta:
        model = Seller
        fields = ("store_name", "store_image", "contact_info")

from django import forms
from .models import RefundRequest, Order

class RefundRequestForm(forms.ModelForm):
    """ ฟอร์มขอคืนเงิน """
    class Meta:
        model = RefundRequest
        fields = ['bank_name', 'account_number', 'account_name', 'refund_reason', 'payment_proof']

class RefundProofForm(forms.ModelForm):
    """ ฟอร์มอัปโหลดสลิปคืนเงิน """
    class Meta:
        model = RefundRequest
        fields = ["refund_proof"]
        widgets = {
            "refund_proof": forms.FileInput(attrs={"class": "form-control"}),
        }

class RefundProofUploadForm(forms.ModelForm):
    class Meta:
        model = RefundRequest
        fields = ["payment_proof"]

from django import forms
from .models import WithdrawalRequest

class WithdrawalForm(forms.ModelForm):
    class Meta:
        model = WithdrawalRequest
        fields = ["amount"]
class WithdrawalProofForm(forms.ModelForm):
    """ ฟอร์มให้แอดมินอัปโหลดสลิปโอนเงิน """
    class Meta:
        model = WithdrawalRequest
        fields = ["payment_proof"]
        widgets = {
            "payment_proof": forms.FileInput(attrs={"class": "form-control"}),
        }

from django import forms
from .models import Comment
class CommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        fields = ['content']
        widgets = {
            'content': forms.Textarea(attrs={'class': 'form-control', 'rows': 2, 'placeholder': 'Write a comment...'}),
        }

from django import forms
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import get_user_model

class CustomPasswordChangeForm(PasswordChangeForm):
    """ ฟอร์มเปลี่ยนรหัสผ่านที่สามารถใช้เพิ่มฟีเจอร์เพิ่มเติม """
    
    class Meta:
        model = get_user_model()
        fields = ('old_password', 'new_password1', 'new_password2')

class ProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = Member  # ✅ ใช้ Member ซึ่งมี 'date_of_birth' ไม่ใช่ 'birthdate'
        fields = ['profile_picture', 'date_of_birth', 'gender']  # ✅ แก้ชื่อให้ตรงกับ models.py
        widgets = {
            'date_of_birth': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),  # ✅ ใช้ date_of_birth
            'gender': forms.Select(attrs={'class': 'form-control'}),
        }

