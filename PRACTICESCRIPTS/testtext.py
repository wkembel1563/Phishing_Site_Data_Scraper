from twilio.rest import Client 

account_sid = 'AC643cb218d386523498c4e54cab0fdcf4' 
auth_token = '4794ef24fc522c0f5569afbd672896f0' 
client = Client(account_sid, auth_token) 
 
client.messages.create(         
    to='+12143648810',
    from_='+19123965665',
    body='test message!' 
) 

