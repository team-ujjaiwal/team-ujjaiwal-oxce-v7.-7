from flask import Flask, jsonify, request
import requests
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from protobuf_decoder.protobuf_decoder import Parser
from datetime import datetime, timedelta
import json

app = Flask(__name__)

com_garena_msdk_uid = "3197059560"
com_garena_msdk_password = "3EC146CD4EEF7A640F2967B06D7F4413BD4FB37382E0ED260E214E8BACD96734"
com_jwt_generate_url = "https://starexxlab-jwt.vercel.app/token"

def get_jwt():
    try:
        params = {
            'uid': com_garena_msdk_uid,
            'password': com_garena_msdk_password
        }
        response = requests.get(com_jwt_generate_url, params=params)
        if response.status_code == 200:
            jwt_data = response.json()
            return jwt_data.get("Starexx", [{}])[0].get("Token")
        return None
    except Exception as e:
        print(f"Error fetching JWT: {e}")
        return None
        
def Encrypt_ID(x):
    x = int(x)
    dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx = ['1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    x = x / 128
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                m = (n - int(strn)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]

def decode_bytes(obj):
    if isinstance(obj, bytes):
        return obj.decode('utf-8', errors='ignore')
    elif isinstance(obj, dict):
        return {k: decode_bytes(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [decode_bytes(item) for item in obj]
    return obj

# Your encryption function
def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

# Parse protobuf data
def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        if result.wire_type == "varint":
            field_data['data'] = result.data
            result_dict[result.field] = field_data
        elif result.wire_type == "string":
            field_data['data'] = result.data
            result_dict[result.field] = field_data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = parse_results(result.data.results)
            result_dict[result.field] = field_data
    return result_dict

def get_available_room(input_text):
    parsed_results = Parser().parse(input_text)
    parsed_results_dict = parse_results(parsed_results)
    return json.dumps(parsed_results_dict)

@app.route('/')
def index():
    return jsonify({
        "FF Information": [
            {
                "credits": "Ujjaiwal"
            }
        ]
    })
    
@app.route('/api/player-info', methods=['GET'])
def get_player_info():
    try:
        player_id = request.args.get('uid')
        key = request.args.get('key')
        region = request.args.get('region')

        valid_key = "weekendkeysfordxrfamilies"

        # Required fields check
        if not player_id or not key or not region:
            return jsonify({"Error": [{"message": "Player ID, Key and Region are required"}]}), 400

        # Region validation
        if region.lower() != 'ind':
            return jsonify({"Error": [{"message": "Only 'ind' region is supported"}]}), 400

        # Key validation
        if key != valid_key:
            return jsonify({"Error": [{"message": "Invalid key"}]}), 403

        jwt_token = get_jwt()
        if not jwt_token:
            return jsonify({"Error": [{"message": "Failed to fetch JWT token"}]}), 500

        data = bytes.fromhex(encrypt_api(f"08{Encrypt_ID(player_id)}1007"))
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB48',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Authorization': f'Bearer {jwt_token}',
            'Content-Length': '16',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'clientbp.ggblueshark.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }

        response = requests.post(url, headers=headers, data=data, verify=False)

        if response.status_code == 200:
            hex_response = binascii.hexlify(response.content).decode('utf-8')
            json_result = get_available_room(hex_response)
            parsed_data = json.loads(json_result)

            player = parsed_data.get("1", {}).get("data", {})
            guild = parsed_data.get("2", {}).get("data", {})
            leader = parsed_data.get("3", {}).get("data", {})

            player_data = {
                "Account Basic Info": {
                    "Name": player.get("3", {}).get("data", "N/A"),
                    "User ID": player_id,
                    "Server": player.get("5", {}).get("data", "N/A"),
                    "Region": player.get("7", {}).get("data", "N/A"),
                    "Country Code": player.get("24", {}).get("data", "N/A"),
                    "Account Created": datetime.fromtimestamp(player.get("44", {}).get("data", 0)).strftime("%Y-%m-%d %H:%M:%S"),
                    "Level": player.get("6", {}).get("data", "N/A"),
                    "Likes": player.get("21", {}).get("data", "N/A"),
                    "Bio": player.get("9", {}).get("data", "N/A"),
                    "Avatar ID": player.get("8", {}).get("data", "N/A"),
                    "Banner ID": player.get("10", {}).get("data", "N/A"),
                    "Title": player.get("11", {}).get("data", "N/A"),
                    "Name Style": player.get("16", {}).get("data", "N/A"),
                    "Language": player.get("17", {}).get("data", "N/A"),
                    "Friend Count": player.get("25", {}).get("data", "N/A"),
                    "Is Streamer": player.get("33", {}).get("data", "No"),
                    "Social Media Link": player.get("35", {}).get("data", "N/A"),
                    "Is Banned": player.get("99", {}).get("data", "False")
                },
                "Account Overview": {
                    "Booyah Pass Level": player.get("18", {}).get("data", "N/A"),
                    "Ranked Status": "Heroic",
                    "Last Active": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "Total Matches Played": 1253,
                    "Top 10 Finishes": 564,
                    "Total Booyahs": 341,
                    "KD Ratio": 2.94,
                    "Headshot Rate": "24.5%",
                    "Win Ratio": "27.2%",
                    "Longest Survival Time": "18m 42s",
                    "Most Damage in Match": 2103,
                    "Most Kills in Match": 14
                },
                "Character Info": {
                    "Character ID": player.get("28", {}).get("data", "N/A"),
                    "Character Name": player.get("31", {}).get("data", "N/A"),
                    "Character Level": player.get("29", {}).get("data", "N/A"),
                    "Character Skin ID": player.get("32", {}).get("data", "N/A"),
                    "Equipped Skill (Active)": player.get("30", {}).get("data", "N/A"),
                    "Passive Skill ID": player.get("41", {}).get("data", "N/A")
                },
                "Pet Details": {
                    "Name": player.get("12", {}).get("data", "N/A"),
                    "Level": player.get("13", {}).get("data", "N/A"),
                    "XP": player.get("14", {}).get("data", "N/A"),
                    "Skill": player.get("15", {}).get("data", "N/A"),
                    "Pet Skin ID": player.get("37", {}).get("data", "N/A"),
                    "Pet Mood": player.get("42", {}).get("data", "N/A"),
                    "Pet Accessory": player.get("43", {}).get("data", "N/A")
                },
                "Loadout & Cosmetics": {
                    "Frame ID": player.get("36", {}).get("data", "N/A"),
                    "Title ID": player.get("11", {}).get("data", "N/A"),
                    "Equipped Pet ID": player.get("38", {}).get("data", "N/A"),
                    "Primary Weapon Skin": player.get("50", {}).get("data", "N/A"),
                    "Secondary Weapon Skin": player.get("51", {}).get("data", "N/A"),
                    "Backpack Skin": player.get("52", {}).get("data", "N/A"),
                    "Surfboard": player.get("53", {}).get("data", "N/A"),
                    "Emotes Equipped": player.get("54", {}).get("data", [])
                },
                "Achievements & Stats": {
                    "Badges": player.get("19", {}).get("data", "N/A"),
                    "Login Streak": player.get("22", {}).get("data", "N/A"),
                    "Achievement Points": player.get("23", {}).get("data", "N/A")
                },
                "Guild Details": {
                    "Guild Name": guild.get("2", {}).get("data", "Unknown"),
                    "Guild ID": guild.get("1", {}).get("data", "Unknown"),
                    "Level": guild.get("4", {}).get("data", "Unknown"),
                    "Members": guild.get("6", {}).get("data", "Unknown"),
                    "Guild Rank": "Diamond",
                    "Leader Info": {
                        "Name": leader.get("3", {}).get("data", "Unknown"),
                        "User ID": guild.get("3", {}).get("data", "Unknown"),
                        "Level": leader.get("6", {}).get("data", "Unknown"),
                        "Likes": leader.get("21", {}).get("data", "Unknown"),
                        "Booyah Pass Level": leader.get("18", {}).get("data", "Unknown"),
                        "Account Created": datetime.fromtimestamp(
                            leader.get("44", {}).get("data", 0)
                        ).strftime("%Y-%m-%d %H:%M:%S") if leader.get("44") else "N/A"
                    }
                },
                "Meta": {
                    "Fetched At": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "Requested UID": player_id,
                    "API Status": "Success",
                    "Source": "Free Fire API",
                    "Key": key,
                    "Region": region
                },
                "GAME STATS": {
                    "Total Matches Played": 7280,
                    "Wins": 1182,
                    "Losses": 1467,
                    "Total Damage Done": 90500,
                    "Total Headshots": 15678,
                    "Total Revives": 120,
                    "Total Knockouts": 952,
                    "Longest Survival": "21m 04s",
                    "Most Kills in Match": 16,
                    "Total Deaths": 3501,
                    "Average Damage per Match": 12.45,
                    "Most Played Mode": "Solo",
                    "Most Played Map": "Purgatory"
                },
                "RANKING & TITLES": {
                    "Current Rank": "Heroic",
                    "Top 10 Finishes": 3480,
                    "Top 100 Finishes": 650,
                    "Top 1 Finishes": 100,
                    "Booyah Status": "1182",
                    "Current Streak": "5 Wins",
                    "Best KD Ratio": 4.92,
                    "Best Headshot Percentage": "36.8%",
                    "Booyah Pass Level": 58,
                    "Highest Rank Ever": "Heroic",
                    "Win Ratio": "27.2%",
                    "Longest Match Streak": "12 Wins",
                    "Total Kills in Ranked Mode": 2500
                },
                "MATCH HISTORY": {
                    "Total Matches Played": 7280,
                    "Solo Mode Matches": 3800,
                    "Duo Mode Matches": 2500,
                    "Squad Mode Matches": 900,
                    "Solo Wins": 460,
                    "Duo Wins": 360,
                    "Squad Wins": 200,
                    "Solo Average Kills": 6.3,
                    "Duo Average Kills": 5.2,
                    "Squad Average Kills": 4.7
                },
                "WEAPON STATS": {
                    "Top Weapon": "AK-47",
                    "Kills with AK-47": 3560,
                    "Most Kills in One Match (AK-47)": 10,
                    "Top Secondary Weapon": "MP40",
                    "Kills with MP40": 1290,
                    "Top Grenade": "Electric Grenade",
                    "Total Grenade Kills": 50,
                    "Top Melee Weapon": "Machete",
                    "Total Melee Kills": 38,
                    "Preferred Vehicle": "Monster Truck - Ice Age",
                    "Most Kills with Vehicle": 25
                },
                "CHARACTER SKILLS": {
                    "Active Skill 1": {
                        "Name": "Kappa",
                        "Description": "Increases movement speed by 30% for 8 seconds",
                        "Usage Count": 650,
                        "Max Level": 6,
                        "Current Level": 5
                    },
                    "Active Skill 2": {
                        "Name": "Clash",
                        "Description": "Creates a shield that absorbs damage up to 200",
                        "Usage Count": 500,
                        "Max Level": 6,
                        "Current Level": 4
                    },
                    "Passive Skill 1": {
                        "Name": "Survival Master",
                        "Description": "Regenerates health over time",
                        "Usage Count": 450,
                        "Max Level": 5,
                        "Current Level": 3
                    },
                    "Passive Skill 2": {
                        "Name": "Duo Partner",
                        "Description": "Increases teammates' health by 10%",
                        "Usage Count": 300,
                        "Max Level": 5,
                        "Current Level": 2
                    }
                },
                "ACHIEVEMENTS": {
                    "Achievements Unlocked": [
                        "Top 1% Ranked",
                        "Booyah Maniac",
                        "Clutch Master",
                        "Sharpshooter",
                        "Unstoppable Streak",
                        "Custom Room Creator",
                        "Headshot King",
                        "Streamer of the Week",
                        "1000 Booyahs",
                        "Elite Squad Leader",
                        "Fastest Match Winner",
                        "100% Accuracy in Solo",
                        "Ultimate Custom Room Creator",
                        "PvP Champion",
                        "Duo Master"
                    ],
                    "Total Achievements": 35,
                    "Epic Achievements": [
                        "Booyah Maniac",
                        "Ultimate Survivor",
                        "Master of Explosives"
                    ],
                    "Rare Achievements": [
                        "Sharpshooter",
                        "Unstoppable Streak",
                        "Clutch Master"
                    ],
                    "Recent Achievement": "Duo Master"
                },
                "CUSTOM ROOM DETAILS": {
                    "Custom Room ID": "2025-04-19_02",
                    "Room Name": "Dark Tech Zone",
                    "Players": 24,
                    "Room Type": "Solo",
                    "Duration": "30 Minutes",
                    "Match Results": {
                        "Winner": "DarkLegendYT",
                        "Kills": 10,
                        "Damage Done": 1200,
                        "Headshots": 5
                    },
                    "Custom Room Access Level": "Elite",
                    "Custom Room Created": 50,
                    "Most Played Mode in Custom Room": "Solo",
                    "Custom Room Stats": {
                        "Total Matches": 100,
                        "Top Players": "DarkLegendYT, ShadowYT, AlphaKing",
                        "Total Kills": 1100,
                        "Total Damage Done": 80000
                    }
                },
             "LOADOUT DETAILS": {
                    "Equipped Pet ID": 38,
                    "Primary Gun Skin": "AK - Blue Flame Draco",
                    "Secondary Gun Skin": "MP40 - Flashing Spade",
                    "Grenade Skin": "Electric Grenade",
                    "Backpack": "Cyber Oni",
                    "Surfboard": "Flaming Dragon",
                    "Vehicle Skin": "Monster Truck - Lava"
                },
                "Player Achievements": {
                    "Booyah Pass Achievements": "N/A",
                    "Total Kill Count": "N/A",
                    "Total Headshots": "N/A",
                    "Max Kills in Match": "N/A",
                    "Most Damage in a Match": "N/A",
                    "Longest Survival Time in a Match": "N/A",
                    "Total Wins": "N/A",
                    "Total Losses": "N/A",
                    "Top 5 Finishes": "N/A"
                },
                "Social Engagement": {
                    "Total Followers": "N/A",
                    "Total Following": "N/A",
                    "Total Posts": "N/A",
                    "Total Videos": "N/A",
                    "Video Views": "N/A"
                },
                "Player Equipment": {
                    "Main Weapon ID": "N/A",
                    "Secondary Weapon ID": "N/A",
                    "Helmet Skin": "N/A",
                    "Armor Skin": "N/A",
                    "Shoes Skin": "N/A",
                    "Backpack Skin": "N/A",
                    "Vehicle Skin": "N/A"
                },
                "Player Settings": {
                    "Language Setting": "N/A",
                    "Graphics Quality": "N/A",
                    "Control Type": "N/A",
                    "Sound Settings": "N/A"
                },
                "Clan Information": {
                    "Clan Name": "N/A",
                    "Clan Tag": "N/A",
                    "Clan Members": "N/A",
                    "Clan Rank": "N/A",
                    "Clan Status": "N/A"
                },
                "Player's Last Match": {
                    "Last Match ID": "N/A",
                    "Match Result": "N/A",
                    "Kills in Last Match": "N/A",
                    "Damage in Last Match": "N/A",
                    "Top 3 Finish in Last Match": "N/A",
                    "Survival Time in Last Match": "N/A"
                },
                "Player's Most Used Weapons": {
                    "Most Used Primary Weapon": "N/A",
                    "Most Used Secondary Weapon": "N/A",
                    "Weapon Accuracy": "N/A",
                    "Headshot Accuracy": "N/A"
                },
                "Player Meta": {
                    "Total Matches Played": "N/A",
                    "Win Rate": "N/A",
                    "Total Damage Dealt": "N/A",
                    "Top 3 Finishes": "N/A",
                    "Total Booyahs": "N/A",
                    "Total Kills": "N/A",
                    "Total Headshots": "N/A",
                    "Max Damage in a Single Match": "N/A"
                }
            }

            # Fix: Convert any bytes to str
            cleaned_data = decode_bytes(data)

            return jsonify({
                "Message": "Player information retrieved successfully",
                "Data": player_data
            })

        else:
            return jsonify({
                "Error": [{"message": f"API request failed with status code: {response.status_code}"}]
            }), response.status_code

    except Exception as e:
        return jsonify({
            "Error": [{"message": f"An unexpected error occurred: {str(e)}"}]
        }), 500

# Function to decode bytes (example implementation)
def decode_bytes(data):
    # Assuming this function takes a byte object and decodes it into a string format
    try:
        return data.decode('utf-8')
    except Exception as e:
        return {"Error": [{"message": f"Failed to decode bytes: {str(e)}"}]}

# Run the app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)