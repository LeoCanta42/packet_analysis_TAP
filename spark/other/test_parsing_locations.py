import requests

# Take the geolocalization from the IP using ipinfo.io
def get_geolocation_ipinfo(ip):
    print("starting")
    with open('ipinfotoken.key', 'r') as file:
        token = file.read().replace('\n', '')
        url = f"https://ipinfo.io/{ip}?token={token}"
        response = requests.get(url)
        json=response.json()
        region='"region":"{}"'.format(json.get("region"))
        location=json.get("loc").split(",")
        parsed_location='"loc":{"lat":'+ location[0] +', "lon":'+ location[1] +'}'
        return region,parsed_location
    
import geocoder

def get_current_gps_coordinates(ip):
    g = geocoder.ip(ip)#this function is used to find the current information using ip
    if g.latlng is not None and g.city is not None: 
        region='"region":"{}"'.format(g.city)
        location=g.latlng
        parsed_location='"loc":{"lat":'+ f"{location[0]}" +', "lon":'+ f"{location[1]}" +'}'
        return region,parsed_location
    else:
        return "ERROR"
    
print(get_current_gps_coordinates("me"))