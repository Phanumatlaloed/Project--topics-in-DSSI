# myapp/templatetags/custom_filters.py
from django import template

register = template.Library()

@register.filter
def get_item(dictionary, key):
    """ ดึงค่า dictionary[key] ถ้ามีค่าอยู่ """
    return dictionary.get(key, None)
