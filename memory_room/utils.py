import string, random
from django.utils.text import slugify

def generate_unique_slug(instance, queryset=None):
    """
    Generate a unique slug for a model instance.
    """
    # slug_base = slugify(getattr(instance, field_name))
    slug_base = slug = slugify(instance.name)

    slug = slug_base
    model_class = instance.__class__
    
    if queryset is None:
        queryset = model_class.objects.all()

    counter = 1
    str_letters = string.ascii_lowercase
    while queryset.filter(slug = slug).exclude(pk=instance.pk).exists():
        slug = slugify(slug + random.choice(str_letters) + str(random.randint(1,9)))
        counter += 1
    
    print(f'Slug created counts: {counter} \n slug:{slug} ')

    return slug
