first run proces_domains.py   
then url_check.py for quick verify for instance the workers.dev space so it looks for 1101 errors  
use url_full.py for good and quick overview during scanning   


```  
Output url_check.py:   
2025-06-20 14:47:51,836 - INFO - Starting URL checks
2025-06-20 14:47:51,837 - INFO - Loaded 101 domains for checking
2025-06-20 14:47:51,837 - INFO - Checking: https://xx.dev
2025-06-20 14:47:52,999 - INFO - Checking: https://xx.dev
2025-06-20 14:47:54,112 - INFO - Checking: https://xx.dev
2025-06-20 14:47:54,190 - ERROR - Connection error for https://9ce471a2.f465c2cb3dde3fb373fb4cf8.workers.dev: HTTPSConnectionPool(host='9ce471a2.f465c2cb3dde3fb373fb4cf8.workers.dev', port=443): Max retries exceeded with url: / (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1007)')))
2025-06-20 14:47:55,197 - INFO - Checking: https://xx.dev
2025-06-20 14:47:56,313 - INFO - Checking: https://xx.dev
2025-06-20 14:48:05,325 - INFO - Checking: https://cookie-consent.deedmob.workers.dev
2025-06-20 14:48:05,429 - WARNING - Cloudflare 1101 error detected on https://cookie-consent.deedmob.workers.dev  
```     

```  
Output url_full.py:    
Domain                                                       | Status                    | HTTP Code  | Details
------------------------------------------------------------------------------------------------------------------------
xx.dev                | UP (Healthy)              | 401        | You need to login....
xxx.dev      | UP (Healthy)              | 404        | <!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE 7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE 8]>    <html class="no-js ie8 oldie" lang="en-US"> <![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js" lang="en-US"> <!--<![endif]-->
  <head>
    <meta charSet="utf-8"/>
    <meta http-equiv="refresh" content="30">
    <title>Page not found</title>
    <link rel="icon" type="image/png" href="https://workers.cloudflar...
   ```