from django.shortcuts import render, redirect
from django.conf import settings
import requests
import re
from bs4 import BeautifulSoup
from django.core.mail import send_mail
import random
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages


# Create your views here.
def home(request):
    if request.method == 'POST':
        results = []
        url = request.POST.get('url')
        #Test the sensible informations disclosure
        if verifier_divulgation_infos_sensibles(url):
            results.append("Le site web divulgue des informations sensibles sur ses utilisateurs.")
        elif verifier_divulgation_infos_sensibles(url) == False:
            results.append("Le site web ne semble pas divulguer d'informations sensibles sur ses utilisateurs.")
        else:
            results.append("Le site web est inatteignable.")

        #Test the critical informations disclosure
        if verifier_divulgation_infos_critiques(url):
            results.append(f"Le site web divulgue des informations critiques sur ses utilisateurs.")
        elif verifier_divulgation_infos_critiques(url) == False:
            results.append("Le site web ne semble pas divulguer d'informations critiques sur ses utilisateurs.")
        else:
            results.append("Le site web est inatteignable.")

        # Afficher les résultats des tests de sécurité
        if analyse_site_securite(url):
            results.append("Le site contient des liens suspects ou/et des scripts malveillants")
        elif analyse_site_securite(url) == False:
            results.append("Le site ne contient pas de liens suspects ni de scripts malveillants")
        else :
            results.append("Le site web est inaccessible.")

        return render(request, "home.html", {'results': results, 'url': url})

    return render(request, "home.html")


def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        firstname = request.POST['firstname']
        lastname = request.POST['lastname']
        email = request.POST['email']
        password = request.POST['password']
        password1 = request.POST['password1']
        if User.objects.filter(username=username):
            messages.error(request, "This username already exists")
            return redirect('register')
        if User.objects.filter(email=email):
            messages.error(request, "This email is already in use")
            return redirect('register')
        if not username.isalnum():
            messages.error(request, "The name must be alphanumeric")
            return redirect('register')
        if password != password1:
            messages.error(request, "The passwords do not match")
            return redirect('register')

        user = User.objects.create_user(username, email, password)
        user.first_name = firstname
        user.last_name = lastname
        user.save()
        messages.success(request, 'Account created successfully')
        return redirect('sign_in')
    return render(request, "register.html")
def sign_in(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            code = ''.join(random.choices('0123456789', k=6))
            send_email(user.email, code)

            request.session['code'] = code
            request.session['user_id'] = user.id
            return redirect('verify')
        else:
            messages.error(request, 'Invalid username or password.')
            return redirect('sign_in')
    return render(request, "Login.html")

def logOut(request):
    logout(request)
    messages.success(request, 'Logged out')
    return redirect('home')

def send_email(email, code):
    message = f'Welcome to the Checkvuln website \n\n here is your confirmation code: {code} \n\n Thank you'
    send_mail(
        subject=f"Checkvuln Confirmation Email",
        message=message,
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[email], fail_silently=False)

def verify(request):
    if 'code' not in request.session or 'user_id' not in request.session:
        return redirect('sign_in')

    if request.method == 'POST':
        entered_code = request.POST['code']
        generate_code = request.session['code']
        if entered_code == generate_code:
            user_id = request.session['user_id']
            user = User.objects.get(id=user_id)
            login(request, user)
            del request.session['code']
            del request.session['user_id']
            return redirect('home')
        else:
            messages.error(request, 'Invalid code.')
            return redirect('verify')

    return render(request, 'verify.html')

def verifier_divulgation_infos_critiques(site_web):
    """
    Fonction qui vérifie si un site web divulgue des informations critiques sur ses utilisateurs.

    Args:
    site_web (str): L'URL du site web à vérifier.

    Returns:
    bool: True si le site web divulgue des informations critiques, False si le site ne divulgue pas des informations critiques
          et None si le site est inatteignable
    """

    try:
        # Requête HTTP pour obtenir le code source du site web
        response = requests.get(site_web)

        # Vérifier si la requête a réussi
        if response.status_code != 200:
            return None

        # Extraire le contenu HTML du site web
        html_content = response.content

        # Analyser le contenu HTML avec BeautifulSoup
        soup = BeautifulSoup(html_content, "html.parser")

        # Rechercher des balises contenant des informations critiques
        balises_critiques = soup.find_all(
            ["input", "textarea", "select", "div"],
            attrs={"type": ["password", "email", "credit-card"]},
        )

        # Vérifier si des informations critiques sont présentes dans le code source
        for balise in balises_critiques:
            if balise.has_attr("value"):
                valeur = balise["value"]
                if valeur and not valeur.startswith("****"):
                    return True

        # Si aucune information critique n'est trouvée, retourner False
        return False
    except requests.exceptions.ConnectionError:
        return None


def verifier_divulgation_infos_sensibles(site_web):
    """
    Fonction qui vérifie si un site web divulgue des informations sensibles sur ses utilisateurs.

    Args:
      site_web (str): URL du site web à analyser.

    Returns:
      bool: True si le site web divulgue des informations sensibles, False si le site ne divulgue pas des informations critiques
          et None si le site est inatteignable
    """
    try:
        # Requête HTTP pour obtenir le code source du site web
        response = requests.get(site_web)
        if response.status_code != 200:
            return None

        # Vérification du code source pour les éléments suivants :
        # - Formulaires de connexion non sécurisés (HTTP)
        # - Mots de passe en clair dans le code source
        # - Fichiers contenant des informations sensibles (ex: base de données)
        # - Scripts de suivi non conformes au RGPD

        if "birthday" in response.text.lower() or "password" in response.text.lower() or "profession" in response.text.lower() or "role" in response.text.lower():
            return True

        if "http://" in response.text or "phone-number" in response.text.lower() or "database" in response.text.lower() or "tracking" in response.text.lower():
            return True

        # Analyse des cookies et des en-têtes HTTP pour les informations sensibles
        # - Cookies non sécurisés (ex: sans flag "Secure")
        # - En-têtes HTTP contenant des informations sensibles (ex: X-Forwarded-For)

        for cookie in response.cookies:
            if not cookie.secure:
                return True

        for header in response.headers:
            if header.lower() in ["x-forwarded-for", "x-real-ip"]:
                return True

        # Conclusion
        # Si aucun élément suspect n'est trouvé, la fonction retourne False
        return False
    except requests.exceptions.ConnectionError:
        return None

def analyse_site_securite(url):
    # Test de la sécurité du site
    try:
        # Récupérer le contenu HTML du site web
        response = requests.get(url)
        if response.status_code != 200:
            #Impossible de récupérer le contenu du site web
            return None

        # Analyser le contenu HTML avec BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')

        # Vérifier les liens suspects
        suspicious_links = []
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href is None:
                continue
            # Rechercher des motifs suspects dans l'URL
            if not re.match("^https://", href) or re.search(r'[^\w\-\.]|phishing|malware|malicious', href, re.IGNORECASE):
                suspicious_links.append(href)

        # Vérifier les scripts malveillants
        malicious_scripts = []
        for script in soup.find_all('script'):
            if re.search(r'eval\(|document\.write\(|malware|malicious', script.get_text(), re.IGNORECASE):
                malicious_scripts.append(script.get_text())

        if suspicious_links or malicious_scripts:
            return True

        return False
    except requests.ConnectionError:
        #Impossible de se connecter au site web
        return None