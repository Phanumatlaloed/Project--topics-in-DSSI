# myapp/templatetags/custom_filters.py
from django import template
from myapp.models import ReviewResponse

register = template.Library()

@register.filter
def get_item(dictionary, key):
    """ ดึงค่า dictionary[key] ถ้ามีค่าอยู่ """
    return dictionary.get(key, None)
@register.simple_tag
def get_review_response(review_id):
    try:
        return ReviewResponse.objects.select_related("seller").get(review_id=review_id)
    except ReviewResponse.DoesNotExist:
        return None