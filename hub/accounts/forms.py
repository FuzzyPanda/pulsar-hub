from django import forms


class SignupForm(forms.Form):
    """Extra fields on allauth's signup form (ACCOUNT_SIGNUP_FORM_CLASS)."""

    name = forms.CharField(max_length=200, label="Your name")
    field_order = ["name", "email", "password1", "password2"]

    def signup(self, request, user):
        user.name = self.cleaned_data["name"].strip()
        user.save(update_fields=["name"])
