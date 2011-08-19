from django import forms

class UserRegistrationForm(forms.Form):
	username = forms.CharField(max_length=30) 
	password = forms.CharField(max_length=30, widget=forms.PasswordInput(render_value=False))
	confirm_password = forms.CharField(max_length=30, widget=forms.PasswordInput(render_value=False))
	first_name = forms.CharField(max_length=30, required=False)
	last_name = forms.CharField(max_length=30, required=False)
	email = forms.EmailField(max_length=30)

