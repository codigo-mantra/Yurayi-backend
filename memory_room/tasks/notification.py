from celery import shared_task


@shared_task
def generate_notification():
    """Fetch active users and return simple report data"""
    response = False
    print('-------- Task execution started --------')
    try:
        print('Notifcation created')
    except Exception as e:
        print('Some exception occur')
        # logger.critical(f'Some exception occurent while testing celery task as')
    else:
        response  = True
    
    finally:
        return response
        
   