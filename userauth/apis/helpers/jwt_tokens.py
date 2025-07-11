from userauth.models import User
from rest_framework_simplejwt.tokens import RefreshToken,AccessToken

# JWTToken Handler
class JWTTokenHandler:
    """It will provide JWT token for registered users like access_token and refresh_token.
       And also it revert user from JWT token as 
    """
    # get token for user
    def get_token_for_user(self, user):
        """This method will return refresh and access token for registered user"""

        try:
            tokens = RefreshToken().for_user(user=user)
        except:
            pass
        else:
            return {
                     'refresh_token': str(tokens),
                     'access_token': str(tokens.access_token)
                    }
    
    # get user from token
    def get_user_from_token(self, token):
        """This function will return current user using token.
            Note : token is required to get the logged-in user.
        """

        user = None

        try:
            # validating user token and fetching user id
            user_token = AccessToken(token=token)
        except:
            pass
        else:
            try:
                # fethcing user from user id
                user = User.objects.get(id = user_token['user_id'])
            except:
                pass
            else:
                if not user:
                    pass
                else:
                    # returning user if found
                    return user