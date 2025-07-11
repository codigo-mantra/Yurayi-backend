from django.utils.text import slugify

def generate_unique_slug(instance, field_name='name', slug_field_name='slug', queryset=None):
    """
    Generate a unique slug for a model instance.
    """
    slug_base = slugify(getattr(instance, field_name))
    slug = slug_base
    model_class = instance.__class__
    
    if queryset is None:
        queryset = model_class.objects.all()

    counter = 1
    while queryset.filter(**{slug_field_name: slug}).exclude(pk=instance.pk).exists():
        slug = f"{slug_base}-{counter}"
        counter += 1

    return slug
