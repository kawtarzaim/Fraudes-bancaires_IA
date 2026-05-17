from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

from .models import Payment


class CustomFormMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs.update({
                'class': 'form-control form-control-dark',
                'autocomplete': 'off',
            })
            if not field.widget.attrs.get('placeholder'):
                field.widget.attrs['placeholder'] = field.label


class RegisterForm(UserCreationForm, CustomFormMixin):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']


class LoginForm(CustomFormMixin, forms.Form):
    username = forms.CharField(max_length=150, label='Username')
    password = forms.CharField(widget=forms.PasswordInput, label='Password')


class PaymentForm(CustomFormMixin, forms.ModelForm):
    class Meta:
        model = Payment
        fields = ['amount', 'payment_type', 'country']
        labels = {
            'amount': 'Payment Amount',
            'payment_type': 'Payment Type',
            'country': 'Payment Country',
        }
        widgets = {
            'amount': forms.NumberInput(attrs={'step': '0.01'}),
            'country': forms.TextInput(attrs={'placeholder': 'Country'}),
        }
