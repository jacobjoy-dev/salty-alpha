from django.contrib import messages
from django.shortcuts import redirect, render

from ..forms import EnquiryForm


def index(request):
    if request.method == "POST":
        form = EnquiryForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Your message has been sent. Thank you!")
            return redirect("index")
        else:
            messages.error(request, "Error in form submission. Please check your inputs.")
    else:
        form = EnquiryForm()
    return render(request, "index.html", {"form": form})
