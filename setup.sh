#!/bin/bash

###############################################################################################
# Get needed dependencies.
###############################################################################################
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo "Informationen zu benötigten Abhängigkeiten werden gesammelt..."

dependencies=("curl" "dialog" "docker" "docker-compose" "wget" "jq" "unzip")
missing_dependencies=()

for dependency in ${dependencies[*]}; do
  dpkg -s "$dependency" > /dev/null 2> /dev/null

  if [[ $? != 0 ]]; then
    missing_dependencies[${#missing_dependencies[@]}]="$dependency"
  fi
done

if [[ ${#missing_dependencies[@]} > 0 ]]; then
  missing_dependencies="${missing_dependencies[*]}"
  echo "Fehlende Abhängigkeiten die installiert werden: $missing_dependencies"

  sudo apt-get --yes update && sudo apt-get --yes install $(echo "$missing_dependencies")

  sleep 1;

  sudo usermod -aG docker $USER
  sudo systemctl enable docker && sudo systemctl start docker
fi
echo "Benötigte Abhängigkeiten sind installiert"
###############################################################################################



###############################################################################################
# Function declerations.
###############################################################################################
DIALOG_TEMP_FILE="/tmp/jitsi_installer"
DOWNLOAD_LINK=""
INSTALL_DIR=""
DIALOG_TITLE=""
IS_FIRST_RUN=1
CURL_TEMP_FILE="/tmp/curl"

function exit_cleanup() {
  PARSED_JSON=""
  JWT=""
  TEMP_VALUES=""
  rm "$DIALOG_TEMP_FILE" "$CURL_TEMP_FILE" 2> /dev/null

  TMP_ID=""
  TMP_FIRSTNAME=""
  TMP_LASTNAME=""
  TMP_EMAIL=""
  TMP_PASSWORD=""
  TMP_MODERATOR=""

  clear
}

PARSED_JSON=""
function parse_json() {
    local PARAMS="$#"
    local JSON=`jq -r "to_entries|map(\"\(.key)=\(.value|tostring)\")|.[]" <<< "$1"`
    local KEYS=''

    if [ $# -gt 1 ]; then
        KEYS="$2"
    fi

    while read -r PAIR; do
        local KEY=''

        if [ -z "$PAIR" ]; then
            break
        fi

        IFS== read PAIR_KEY PAIR_VALUE <<< "$PAIR"

        if [ -z "$KEYS" ]; then
            KEY="$PAIR_KEY"
        else
            KEY="$KEYS:$PAIR_KEY"
        fi

        if jq -e . >/dev/null 2>&1 <<< "$PAIR_VALUE"; then
            parse_json "$PAIR_VALUE" "$KEY"
        else
            PARSED_JSON["$KEY"]="$PAIR_VALUE"
        fi
    done <<< "$JSON"
}

function read_from_dialog_result_file() {
  CONTENT=$(cat "$DIALOG_TEMP_FILE")
  echo "$CONTENT"
}

function check_settings() {
  dialog --colors --output-fd 3 --no-cancel --title "Überprüfung" --menu "Daten überprüfen" 0 0 5 \
    "1) Download Adresse" "$DOWNLOAD_LINK" \
    "2) Installationsordner" "$INSTALL_DIR" \
    "9) Fortfahren" "" \
    3> "$DIALOG_TEMP_FILE"

    OPTION=$(read_from_dialog_result_file)
    OPTION=${OPTION:0:1}

    case $OPTION in
      1) # Downloadlink
        dialog --colors --output-fd 3 --no-cancel --title "Download Adresse" --inputbox "Bitte geben Sie die Adresse zum Dowload der \Zbjitsi_release.zip\Zn an" 0 0 "https://" 3> "$DIALOG_TEMP_FILE"
        DOWNLOAD_LINK=$(read_from_dialog_result_file)
        check_settings
        ;;

      2) # Installation folder
        dialog --colors --output-fd 3 --no-cancel --title "Bitte Installationsordner auswählen" --dselect "$SCRIPT_DIR" 0 0 3> "$DIALOG_TEMP_FILE"
        INSTALL_DIR=$(read_from_dialog_result_file)
        check_settings
        ;;

      *)
        ;;
    esac
}

function run_installation() {
  mkdir -p "$INSTALL_DIR"
  cd "$INSTALL_DIR"

  # Check if jitsi_release.zip is 
  if [[ ! -f "$INSTALL_DIR/jitsi_release.zip" ]]; then
    dialog --colors --no-cancel --title "$DIALOG_TITLE" --yesno "Die ZIP Datei \Zbjitsi_release.zip\Zn wurde im Installationsordner nicht gefunden.\n\nSoll diese jetzt heruntergeladen werden?" 0 0

    if [[ $? == 0 ]]; then
      wget -N -O "$INSTALL_DIR/jitsi_release.zip" --progress=dot "$DOWNLOAD_LINK" 2>&1 |\
      grep "%" |\
      sed -u -e "s,\.,,g" | awk '{print $2}' | sed -u -e "s,\%,,g"  | dialog --gauge "Lade Jitsi Release herunter..." 0 40
    else
      dialog --colors --no-cancel --title "$DIALOG_TITLE" --msgbox "Die Installation wurde abgebrochen." 0 0
      return 1
    fi
  fi

  (
    echo "0"; sleep 1;
    echo "XXX"; echo "Jitsi entpacken..."; echo "XXX";
    unzip -o jitsi_release.zip;

    echo "30"; sleep 2;
    echo "XXX"; echo "Setze Dateiberechtigungen..."; echo "XXX";
    chmod +x gen-config-folders.sh;
    chmod +x gen-passwords.sh;

    echo "50"; sleep 2;
    echo "XXX"; echo "Konfigurationsdateien bereitstellen..."; echo "XXX";
    cp env.example .env > /dev/null 2> /dev/null;
    ./gen-config-folders.sh > /dev/null 2> /dev/null;
    ./gen-passwords.sh > /dev/null 2> /dev/null;

    echo "80"; sleep 2;
    echo "XXX"; echo "Importiere Container..."; echo "XXX";
    docker load -i jitsi_modified.tar;

    echo "100";
    echo "XXX"; echo "Installation erfolgreich beendet"; echo "XXX"; sleep 3;
  ) | dialog --colors --title "$DIALOG_TITLE" --gauge "Installation von Jitsi" 0 60
}

function show_menu_start_stop() {
  DIALOG_TITLE="Jitsi Starten/Stoppen"

  OPTION=$(
    dialog --colors --stdout --no-cancel --title "$DIALOG_TITLE" --menu "" 0 0 5 \
      "<--" "Zurück zum Hauptmenü" \
      "1)" "Jitsi Starten" \
      "2)" "Jitsi Neustarten" \
      "3)" "Jitsi Stoppen"
  )
  OPTION=${OPTION:0:1}

  cd "$INSTALL_DIR"
  case $OPTION in
    1)
      ./gen-config-folders.sh;

      (
        docker-compose up --detach 2>&1
      ) | dialog --colors --title "$DIALOG_TITLE" --progressbox "Docker Ausgabe" 40 60
      
      docker exec jitsi-web-1 "/usr/share/jitsi-meet/transcripts/deploy.sh"

      if [[ "$IS_FIRST_RUN" == 1 ]]; then
        (
          (
            docker-compose down && \
              docker volume rm -f jitsi_postgres_data && \
              docker-compose up -d
          ) 2>&1
        ) | dialog --colors --title "$DIALOG_TITLE" --progressbox "Docker Ausgabe" 40 60

        IS_FIRST_RUN=0
        echo "IS_FIRST_RUN=$IS_FIRST_RUN" >> "$SCRIPT_DIR/.installer-config"
      fi
      ;;
    
    2)
      (
        (docker-compose down && docker-compose up -d) 2>&1
      ) | dialog --colors --title "$DIALOG_TITLE" --progressbox "Docker Ausgabe" 40 60

      docker exec jitsi-web-1 "/usr/share/jitsi-meet/transcripts/deploy.sh"

      if [[ "$IS_FIRST_RUN" == 1 ]]; then
        (
          (
            docker-compose down && \
              docker volume rm -f jitsi_postgres_data && \
              docker-compose up -d
          ) 2>&1
        ) | dialog --colors --title "$DIALOG_TITLE" --progressbox "Docker Ausgabe" 40 60

        IS_FIRST_RUN=0
        echo "IS_FIRST_RUN=$IS_FIRST_RUN" >> "$SCRIPT_DIR/.installer-config"
      fi
      ;;

    3)
      (
        docker-compose down 2>&1
      ) | dialog --colors --title "$DIALOG_TITLE" --progressbox "Docker Ausgabe" 40 60
      ;;

    *)
      show_menu
      ;;
  esac

  show_menu_start_stop
}

function show_config_visitor() {
  DIALOG_TITLE="Zuschauer Einstellungen"

  cd "$INSTALL_DIR"

  allowViewerToSpeak=OFF
  allowViewerToSpeak=$(
    awk -r '$1 ~ /allowViewerToSpeak/ {print $0}' "custom/web/custom-config.js" \
      | cut -d ' ' -f3
  )

  if [[ -z "$allowViewerToSpeak" || "$allowViewerToSpeak" == false ]]; then
    allowViewerToSpeak=OFF
  else
    allowViewerToSpeak=ON
  fi
  

  TMP="$allowViewerToSpeak"
  VALUES=$(
    dialog --colors --no-cancel --stdout --title "$DIALOG_TITLE" --checklist "" 0 0 5 \
      "1)" "Zuschauer das Sprechen erlauben" "$allowViewerToSpeak"
  )

  SETTINGS_CHANGED=false

  if [[ ( "${VALUES[*]}" =~ "1\)" && "$allowViewerToSpeak" == "OFF" ) || ( "$allowViewerToSpeak" == "ON" && ! "${VALUES[*]}" =~ "1\)" ) ]]; then
    SETTINGS_CHANGED=true

    if [[ ! "${VALUES[*]}" =~ "1\)" ]]; then
      sed -i.bak \
        -e "s#config.custom.allowViewerToSpeak\s*=\s*.*#config.custom.allowViewerToSpeak = false#g" \
        "custom/web/custom-config.js"
    else
      sed -i.bak \
        -e "s#config.custom.allowViewerToSpeak\s*=\s*.*#config.custom.allowViewerToSpeak = true#g" \
        "custom/web/custom-config.js"
    fi
  fi

  if [[ "$SETTINGS_CHANGED" == true ]]; then
    dialog --colors --title "$DIALOG_TITLE" --yesno "Änderungen sind vorhanden.\n\nSoll der Container wieder neu gestartet?" 0 0

    if [[ $? == 0 ]]; then
      (
        (docker-compose down && docker-compose up -d) 2>&1
      ) | dialog --colors --title "$DIALOG_TITLE" --progressbox "Docker Ausgabe" 40 60

      docker exec jitsi-web-1 "/usr/share/jitsi-meet/transcripts/deploy.sh"
    fi
  fi

  show_menu_configuration
}

function show_menu_configuration() {
  DIALOG_TITLE="Jitsi Konfiguration"
  
  OPTION=$(
    dialog --colors --stdout --no-cancel --title "$DIALOG_TITLE" --menu "" 0 0 5 \
      "<--" "Zurück zum Hauptmenü" \
      "1)" "Zuschauer - Einstellungen"
      # "2)" "Let's Encrypt Konfiguration"
  )

  OPTION=${OPTION:0:1}
  case $OPTION in
    1)
      show_config_visitor
      ;;

    # 2)
    #   show_config_letsencrypt
    #   ;;

    *)
      show_menu
      ;;
  esac
}

JWT=""
TMP_VALUES=""
function show_menu_login() {
  DIALOG_TITLE="Benutzerverwaltung"

  if [[ -z "$JWT" ]]; then
    # Show login dialog.
    dialog --colors --output-fd 3 --insecure --title "$DIALOG_TITLE" --mixedform "Bitte anmelden" 0 0 10 \
      "E-Mail:"   1 1 "${TMP_VALUES[0]}" 1 15 30 0 0 \
      "Passwort:" 2 1 "${TMP_VALUES[1]}" 2 15 30 0 1 \
      3> "$DIALOG_TEMP_FILE"

    if [[ "$?" == 1 ]]; then
      show_menu
      return 1
    fi

    TMP_VALUES=()
    while IFS= read -r line; do
      TMP_VALUES+=("$line")
    done < "$DIALOG_TEMP_FILE"

    CURL_STATUS=$(
      curl -k -o "$CURL_TEMP_FILE" \
        -X POST \
        -H 'Content-Type: application/json' \
        -d "{\"email\":\"${TMP_VALUES[0]}\",\"password\":\"${TMP_VALUES[1]}\"}" \
        -s -w "%{http_code}\n" \
        https://localhost/token
    )

    if [[ "$CURL_STATUS" != 200 ]]; then
      dialog --colors --title "$DIALOG_TITLE" --msgbox "E-Mail oder Passwort ist falsch" 0 0
      show_menu_login
      return 1
    fi

    JSON=$(cat "$CURL_TEMP_FILE")
    parse_json "$JSON"
    JWT="${PARSED_JSON[data]}"
  fi

  PARSED_JWT=$(jq -R 'gsub("-";"+") | gsub("_";"/") | split(".") | .[1] | @base64d | fromjson' <<< "$JWT")
  IS_ADMIN=$(jq -r '.add | .user | .isModerator' <<< "$PARSED_JWT")

  if [[ $IS_ADMIN == false ]]; then
    JWT=""
    dialog --colors --title "$DIALOG_TITLE" --msgbox "Nur Administratoren/Moderatoren dürfen diesen Bereich bearbeiten" 0 0
    show_menu_login
    return 1
  fi

  show_menu_users
}

function show_menu_user_show() {
  show_users "Benutzer anzeigen"

  TMP_ID="${TMP_SELECTED_USER[0]}"
  TMP_FIRSTNAME="${TMP_SELECTED_USER[2]}"
  TMP_LASTNAME="${TMP_SELECTED_USER[3]}"
  TMP_EMAIL="${TMP_SELECTED_USER[1]}"
  TMP_PASSWORD=""
  TMP_MODERATOR="${TMP_SELECTED_USER[4]}"

  if [[ $TMP_MODERATOR == true ]]; then
    TMP_MODERATOR="J"
  else
    TMP_MODERATOR="N"
  fi

  DIALOG_TITLE="Benutzer bearbeiten"

  dialog --colors --insecure --title "$DIALOG_TITLE" --mixedform "" 30 60 5 \
    "Vorname"  1 1 "$TMP_FIRSTNAME" 1 20 30 100 2 \
    "Nachname" 2 1 "$TMP_LASTNAME" 2 20 30 100 2 \
    "E-Mail"   3 1 "$TMP_EMAIL" 3 20 30 100 2 \
    "Moderator" 5 1 "$TMP_MODERATOR" 5 20 2 1 2

  TMP_ID=""
  TMP_FIRSTNAME=""
  TMP_LASTNAME=""
  TMP_EMAIL=""
  TMP_PASSWORD=""
  TMP_MODERATOR=""

  show_menu_users
}

function show_menu_user_edit() {
  show_users "Benuter zum Bearbeiten auswählen"

  TMP_ID="${TMP_SELECTED_USER[0]}"
  TMP_FIRSTNAME="${TMP_SELECTED_USER[2]}"
  TMP_LASTNAME="${TMP_SELECTED_USER[3]}"
  TMP_EMAIL="${TMP_SELECTED_USER[1]}"
  TMP_PASSWORD=""
  TMP_MODERATOR="${TMP_SELECTED_USER[4]}"

  if [[ $TMP_MODERATOR == true ]]; then
    TMP_MODERATOR="J"
  else
    TMP_MODERATOR="N"
  fi

  DIALOG_TITLE="Benutzer bearbeiten"

  dialog --colors --insecure --output-fd 3 --title "$DIALOG_TITLE" --mixedform "" 30 60 5 \
    "Vorname"  1 1 "$TMP_FIRSTNAME" 1 20 30 100 0 \
    "Nachname" 2 1 "$TMP_LASTNAME" 2 20 30 100 0 \
    "E-Mail"   3 1 "$TMP_EMAIL" 3 20 30 100 0 \
    "Passwort" 4 1 "$TMP_PASSWORD" 4 20 30 100 1 \
    "Moderator" 5 1 "$TMP_MODERATOR" 5 20 2 1 0 \
    3> "$DIALOG_TEMP_FILE"

  if [[ $? == 1 ]]; then
    show_menu_users
    return 1
  fi

  VALUES=()
  while IFS= read -r line; do
    VALUES+=("$line")
  done < "$DIALOG_TEMP_FILE"

  TMP_FIRSTNAME="${VALUES[0]}"
  TMP_LASTNAME="${VALUES[1]}"
  TMP_EMAIL="${VALUES[2]}"
  
  if [[ "${#VALUES[@]}" > 4 ]]; then
    TMP_PASSWORD="${VALUES[3]}"
    TMP_MODERATOR="${VALUES[4]}"
  else
    TMP_MODERATOR="${VALUES[3]}"
  fi

  if [[ -z "$TMP_FIRSTNAME" ]]; then
    dialog --colors --no-cancel --title "$DIALOG_TITLE" --msgbox "Vorname ist nicht angegeben" 0 0
    show_menu_user_edit
    return 1
  fi

  if [[ -z "$TMP_LASTNAME" ]]; then
    dialog --colors --no-cancel --title "$DIALOG_TITLE" --msgbox "Nachname ist nicht angegeben" 0 0
    show_menu_user_edit
    return 1
  fi

  if [[ -z "$TMP_EMAIL" ]]; then
    dialog --colors --no-cancel --title "$DIALOG_TITLE" --msgbox "E-Mail ist nicht angegeben" 0 0
    show_menu_user_edit
    return 1
  fi

  if [[ -z "$TMP_MODERATOR" ]]; then
    dialog --colors --no-cancel --title "$DIALOG_TITLE" --msgbox "Moderator ist nicht angegeben" 0 0
    show_menu_user_edit
    return 1
  fi

  if [[ ! "$TMP_MODERATOR" =~ ^[jJnN]{1}$ ]]; then
    dialog --colors --no-cancel --title "$DIALOG_TITLE" --msgbox "Moderator muss J oder N sein" 0 0
    show_menu_user_edit
  else
    if [[ "$TMP_MODERATOR" =~ ^[jJ]$ ]]; then
      TMP_MODERATOR=true
    else
      TMP_MODERATOR=false
    fi
  fi

  CURL_STATUS=404
  if [[ -z "$TMP_PASSWORD" ]]; then
    CURL_STATUS=$(
      curl -k -o "$CURL_TEMP_FILE" \
        -X POST \
        -H 'Content-Type: application/json' \
        -d "{\"jwt\":\"$JWT\", \"id\":\"$TMP_ID\", \"firstName\":\"$TMP_FIRSTNAME\", \"lastName\":\"$TMP_LASTNAME\", \"email\":\"$TMP_EMAIL\", \"isModerator\":$TMP_MODERATOR}" \
        -s -w "%{http_code}\n" \
        https://localhost/token/user/update
    )
  else
    CURL_STATUS=$(
      curl -k -o "$CURL_TEMP_FILE" \
        -X POST \
        -H 'Content-Type: application/json' \
        -d "{\"jwt\":\"$JWT\", \"id\":\"$TMP_ID\", \"firstName\":\"$TMP_FIRSTNAME\", \"lastName\":\"$TMP_LASTNAME\", \"email\":\"$TMP_EMAIL\", \"password\":\"$TMP_PASSWORD\", \"isModerator\":$TMP_MODERATOR}" \
        -s -w "%{http_code}\n" \
        https://localhost/token/user/update
    )
  fi

  

  if [[ "$CURL_STATUS" != 200 ]]; then
    dialog --colors --no-cancel --title "$DIALOG_TITLE" --msgbox "Der Benutzer konnte nicht gespeichert werden." 0 0
    show_menu_user_edit
    return 1
  fi

  dialog --colors --no-cancel --title "$DIALOG_TITLE" --msgbox "Der Benutzer wurde gespeichert" 0 0
  
  rm "$DIALOG_TEMP_FILE"

  TMP_ID=""
  TMP_FIRSTNAME=""
  TMP_LASTNAME=""
  TMP_EMAIL=""
  TMP_PASSWORD=""
  TMP_MODERATOR=""

  show_menu_users
}

function show_menu_user_remove() {
  show_users "Benutzer zum Entfernen auswählen"

  DIALOG_TITLE="Benuter löschen"

  TMP_ID="${TMP_SELECTED_USER[0]}"
  TMP_EMAIL="${TMP_SELECTED_USER[1]}"

  dialog --colors --no-cancel --defaultno --title "$DIALOG_TITLE" --yesno "Sind Sie sicher, dass sie den Benutzer mit der E-Mail \"\Z1$TMP_EMAIL\Zn\" löschen wollen?" 20 40

  if [[ $? == 0 ]]; then
    CURL_STATUS=$(
      curl -k -o "$CURL_TEMP_FILE" \
        -X POST \
        -H 'Content-Type: application/json' \
        -d "{\"jwt\":\"$JWT\", \"id\":\"$TMP_ID\", \"email\":\"$TMP_EMAIL\"}" \
        -s -w "%{http_code}\n" \
        https://localhost/token/user/delete
    )

    if [[ "$CURL_STATUS" == 200 ]]; then
      dialog --colors --title "$DIALOG_TITLE" --msgbox "Der Benutzer wurde erfolgreich gelöscht" 20 40
    else
      dialog --colors --title "$DIALOG_TITLE" --msgbox "Der Benutzer konnte nicht gelöscht werden" 20 40

    fi
  fi

  TMP_ID=""
  TMP_FIRSTNAME=""
  TMP_LASTNAME=""
  TMP_EMAIL=""
  TMP_PASSWORD=""
  TMP_MODERATOR=""

  show_menu_user_remove
}

function show_menu_users() {
  DIALOG_TITLE="Benutzermenü"

  OPTION=$(
    dialog --colors --stdout --no-cancel --title "$DIALOG_TITLE" --menu "" 0 0 5 \
      "<--" "Zurück zum Hauptmenü" \
      "1)" "Benutzer anzeigen" \
      "2)" "Benutzer hinzufügen" \
      "3)" "Benutzer bearbeiten" \
      "4)" "Benutzer entfernen"
  )

  OPTION=${OPTION:0:1}

  case $OPTION in
    1)
      show_menu_user_show
      ;;

    2)
      show_menu_user_add
      ;;

    3)
      show_menu_user_edit
      ;;

    4)
      show_menu_user_remove
      ;;

    *)
      show_menu
      ;;
  esac
}

TMP_ID=""
TMP_FIRSTNAME=""
TMP_LASTNAME=""
TMP_EMAIL=""
TMP_PASSWORD=""
TMP_MODERATOR=""
function show_menu_user_add() {
  DIALOG_TITLE="Benutzer hinzufügen"

  dialog --colors --insecure --output-fd 3 --title "$DIALOG_TITLE" --mixedform "" 30 60 5 \
    "Vorname"  1 1 "$TMP_FIRSTNAME" 1 20 30 100 0 \
    "Nachname" 2 1 "$TMP_LASTNAME" 2 20 30 100 0 \
    "E-Mail"   3 1 "$TMP_EMAIL" 3 20 30 100 0 \
    "Passwort" 4 1 "$TMP_PASSWORD" 4 20 30 100 1 \
    "Moderator" 5 1 "$TMP_MODERATOR" 5 20 2 1 0 \
    3> "$DIALOG_TEMP_FILE"

  if [[ $? == 1 ]]; then
    show_menu_users
    return 1
  fi

  VALUES=()
  while IFS= read -r line; do
    VALUES+=("$line")
  done < "$DIALOG_TEMP_FILE"

  TMP_FIRSTNAME="${VALUES[0]}"
  TMP_LASTNAME="${VALUES[1]}"
  TMP_EMAIL="${VALUES[2]}"
  TMP_PASSWORD="${VALUES[3]}"
  TMP_MODERATOR="${VALUES[4]}"

  if [[ -z "$TMP_FIRSTNAME" ]]; then
    dialog --colors --no-cancel --title "$DIALOG_TITLE" --msgbox "Vorname ist nicht angegeben" 0 0
    show_menu_user_add
    return 1
  fi

  if [[ -z "$TMP_LASTNAME" ]]; then
    dialog --colors --no-cancel --title "$DIALOG_TITLE" --msgbox "Nachname ist nicht angegeben" 0 0
    show_menu_user_add
    return 1
  fi

  if [[ -z "$TMP_EMAIL" ]]; then
    dialog --colors --no-cancel --title "$DIALOG_TITLE" --msgbox "E-Mail ist nicht angegeben" 0 0
    show_menu_user_add
    return 1
  fi

  if [[ -z "$TMP_PASSWORD" ]]; then
    dialog --colors --no-cancel --title "$DIALOG_TITLE" --msgbox "Passwort ist nicht angegeben" 0 0
    show_menu_user_add
    return 1
  fi

  if [[ -z "$TMP_MODERATOR" ]]; then
    dialog --colors --no-cancel --title "$DIALOG_TITLE" --msgbox "Moderator ist nicht angegeben" 0 0
    show_menu_user_add
    return 1
  fi

  if [[ ! "$TMP_MODERATOR" =~ ^[jJnN]{1}$ ]]; then
    dialog --colors --no-cancel --title "$DIALOG_TITLE" --msgbox "Moderator muss J oder N sein" 0 0
    show_menu_user_add
  else
    if [[ "$TMP_MODERATOR" =~ ^[jJ]$ ]]; then
      TMP_MODERATOR=true
    else
      TMP_MODERATOR=false
    fi
  fi

  CURL_STATUS=$(
      curl -k -o "$CURL_TEMP_FILE" \
        -X POST \
        -H 'Content-Type: application/json' \
        -d "{\"jwt\":\"$JWT\", \"firstName\":\"$TMP_FIRSTNAME\", \"lastName\":\"$TMP_LASTNAME\", \"email\":\"$TMP_EMAIL\", \"password\":\"$TMP_PASSWORD\", \"isModerator\":$TMP_MODERATOR}" \
        -s -w "%{http_code}\n" \
        https://localhost/token/user/add
  )

  if [[ "$CURL_STATUS" != 200 ]]; then
    dialog --colors --no-cancel --title "$DIALOG_TITLE" --msgbox "Der Benutzer konnte nicht gespeichert werden." 0 0
    show_menu_user_add
    return 1
  fi

  dialog --colors --no-cancel --title "$DIALOG_TITLE" --msgbox "Der Benutzer wurde gespeichert" 0 0
  
  rm "$DIALOG_TEMP_FILE"

  TMP_ID=""
  TMP_FIRSTNAME=""
  TMP_LASTNAME=""
  TMP_EMAIL=""
  TMP_PASSWORD=""
  TMP_MODERATOR=""

  show_menu_user_add
}

TMP_USERS=()
TMP_SELECTED_USER=()
TMP_NUM_USERS=0
function show_users() {
  TMP_USERS=()
  TMP_SELECTED_USER=()
  TMP_NUM_USERS=0

  DIALOG_TITLE="${1:-"Benutzer anzeigen"}"

  CURL_STATUS=$(
      curl -k -o "$CURL_TEMP_FILE" \
        -X POST \
        -H 'Content-Type: application/json' \
        -d "{\"jwt\":\"$JWT\"}" \
        -s -w "%{http_code}\n" \
        https://localhost/token/user
  )

  JSON_ARRAY=()
  for k in $(jq '.data | keys | .[]' "$CURL_TEMP_FILE"); do
    value=$(jq -r ".data | .[$k]" "$CURL_TEMP_FILE")
    id=$(jq -r '.id' <<< "$value")
    email=$(jq -r '.email' <<< "$value")
    firstname=$(jq -r '.firstName' <<< "$value")
    lastname=$(jq -r '.lastName' <<< "$value")
    moderator=$(jq -r '.isModerator' <<< "$value")

    JSON_ARRAY+=("$id,$email,$firstname,$lastname,$moderator")

    ((TMP_NUM_USERS++))
  done

  rm "$DIALOG_TEMP_FILE"
  for ((i=0;i<TMP_NUM_USERS;i++)) do
    j=$(( $i + 1 ))

    IFS=',' read -r -a tmp <<< ${JSON_ARRAY[$i]}

    echo "$j ${tmp[1]//\"/}" >> "$DIALOG_TEMP_FILE"
  done

  TAGS=$(read_from_dialog_result_file)

  OPTION=$(
    dialog --colors --stdout --no-cancel --title "$DIALOG_TITLE" --menu "" 0 0 5 \
      "<--" "Zurück" \
      $(echo "${TAGS[@]}")
  )

  OPTION=${OPTION:0:1}

  if [[ ! $OPTION =~ ^[0-9]$ ]]; then
    show_menu_users
    return 1
  fi

  INDEX=$( expr $OPTION - 1 )
  IFS=' ' read -r -a tmp <<< "${JSON_ARRAY[$INDEX]}"
  IFS=',' read -r -a TMP_SELECTED_USER <<< "${tmp[@]}"
}

function show_menu() {
  cd "$SCRIPT_DIR"

  DIALOG_TITLE="Hauptmenü"

  dialog --colors --output-fd 3 --no-cancel --title "$DIALOG_TITLE" --menu "" 0 0 5 \
    "1)" "Jitsi Starten/Stoppen" \
    "2)" "Jitsi Konfiguration" \
    "3)" "Benutzereinstellungen" \
    "" "" \
    "7)" "Jitsi Installation durchführen" \
    "" "" \
    "9)" "Beenden" \
    3> "$DIALOG_TEMP_FILE"
  
  OPTION=$(read_from_dialog_result_file)
  OPTION=${OPTION:0:1}

  case $OPTION in
    1)
      show_menu_start_stop
      ;;

    2)
      show_menu_configuration
      ;;
    
    3)
      show_menu_login
      ;;

    7)
      run_first_install
      ;;
    
    9)
      exit 0
      ;;

    *)
      show_menu
      ;;
  esac
}

function run_first_install() {
  IS_FIRST_RUN=1

  dialog --colors --output-fd 3 --no-cancel --title "Download Adresse" --inputbox "Bitte geben Sie die Adresse zum Dowload der \Zbjitsi_release.zip\Zn an" 10 60 "$DOWNLOAD_LINK" 3> "$DIALOG_TEMP_FILE"
  DOWNLOAD_LINK=$(read_from_dialog_result_file)

  if [[ -z "$INSTALL_DIR" ]]; then
    dialog --colors --output-fd 3 --no-cancel --title "Bitte Installationsordner auswählen" --dselect "$SCRIPT_DIR/jitsi" 10 30 3> "$DIALOG_TEMP_FILE"
  else
    dialog --colors --output-fd 3 --no-cancel --title "Bitte Installationsordner auswählen" --dselect "$INSTALL_DIR" 10 30 3> "$DIALOG_TEMP_FILE"
  fi
  INSTALL_DIR=$(read_from_dialog_result_file)

  check_settings

  if [[ ! -f "$SCRIPT_DIR/.installer-config" ]]; then
    touch "$SCRIPT_DIR/.installer-config"
    echo "INSTALL_DIR=$INSTALL_DIR" >> "$SCRIPT_DIR/.installer-config"
    echo "DOWNLOAD_LINK=$DOWNLOAD_LINK" >> "$SCRIPT_DIR/.installer-config"
  else
    FILE="$SCRIPT_DIR/.installer-config"

    sed -i.bak \
      -e "s#INSTALL_DIR=.*#INSTALL_DIR=$INSTALL_DIR#g" \
      -e "s#DOWNLOAD_LINK=.*#DOWNLOAD_LINK=$DOWNLOAD_LINK#g" \
      FILE
  fi

  DIALOG_TITLE="Jitsi Installation"
  dialog --colors --title "$DIALOG_TITLE" --msgbox "Die Installation Ihres Jitsi's wird im nächsten Schritt durchgeführt" 0 0

  run_installation

  show_menu
}
###############################################################################################



###############################################################################################
# Script execution.
###############################################################################################
trap exit_cleanup EXIT

if [[ ! -f "./.installer-config" ]]; then
  dialog --msgbox "Es wurde die erstmalige Installation erkannt\n\nIn den kommenden Schritten, werden Sie durch benötigten Konfigurationsparameter durchgeführt." 0 0
  run_first_install
else
  INSTALL_DIR=$(awk -F= '$1=="INSTALL_DIR"{print $2;exit}' "$SCRIPT_DIR/.installer-config")
  DOWNLOAD_LINK=$(awk -F= '$1=="DOWNLOAD_LINK"{print $2;exit}' "$SCRIPT_DIR/.installer-config")

  show_menu
fi
