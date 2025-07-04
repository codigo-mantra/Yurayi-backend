# TimeCapsoul

TimeCapsoul is a Django-based web application that allows users to create and manage digital time capsules.

## Project Structure

```
timecapsoul/
├── manage.py
├── timecapsoul/
│   ├── __init__.py
│   ├── asgi.py
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
└── website/
    ├── __init__.py
    ├── admin.py
    ├── apps.py
    ├── models.py
    ├── serializers.py
    ├── tests.py
    ├── urls.py
    └── views.py
```

## Setup

1. Create and activate a virtual environment:
```bash
python -m venv env
source env/Scripts/activate  # On Windows
```

2. Install dependencies:
```bash
pip install django
```

3. Run migrations:
```bash
python manage.py migrate
```

4. Start the development server:
```bash
python manage.py runserver
```

## Features

- Django-based web application
- RESTful API support with Django REST framework
- SQLite database for development

## Development

- The project uses Django's MVT (Model-View-Template) architecture
- API endpoints are defined in `website/urls.py`
- Models are defined in `website/models.py`
- Views are defined in `website/views.py`

## License

This project is licensed under the MIT License - see the LICENSE file for details.