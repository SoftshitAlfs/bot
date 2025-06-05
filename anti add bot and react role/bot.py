
import os
import discord
import logging
import requests
from discord.ext import commands
from dotenv import load_dotenv
load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s')
logger = logging.getLogger('discord_bot')
intents = discord.Intents.default()
intents.members = True
intents.guilds = True
intents.message_content = True  
bot = commands.Bot(command_prefix='!', intents=intents)
invites = {}
async def query_virustotal(url):
    import base64
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        submit_response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
        if submit_response.status_code not in [200, 201]:
            logger.error(f"Failed to submit URL to VirusTotal: {submit_response.status_code} {submit_response.text}")
            return None
        analysis_id = submit_response.json().get('data', {}).get('id')
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        url_report = requests.get(analysis_url, headers=headers)
        if url_report.status_code == 200:
            data = url_report.json()
            stats = data.get("data", {}).get("attributes", {}).get("stats", {})
            return {"stats": stats, "analysis_id": analysis_id}
        else:
            logger.error(f"Failed to get URL report: {url_report.status_code} {url_report.text}")
            return None
    except Exception as e:
        logger.error(f"Error querying VirusTotal: {e}")
        return None

@bot.event
async def on_ready():
    logger.info(f'Logged in as {bot.user} (ID: {bot.user.id})')
    logger.info('------')

  
    activity = discord.Game(name="WATCHING ORCA SERVERS")
    await bot.change_presence(status=discord.Status.online, activity=activity)
    
    for guild in bot.guilds:
        invites[guild.id] = await guild.invites()
        logger.debug(f'Cached invites for guild: {guild.name} ({guild.id})')
@bot.event
async def on_guild_join(guild):
    invites[guild.id] = await guild.invites()
    logger.debug(f'Cached invites for new guild: {guild.name} ({guild.id})')
@bot.event
async def on_member_join(member):
    logger.debug(f'Member joined: {member} (bot={member.bot})')
    if member.bot:
        try:       
            async for entry in member.guild.audit_logs(limit=5, action=discord.AuditLogAction.bot_add):
                if entry.target.id == member.id:
                    inviter = entry.user
                    logger.info(f'Bot {member} was added by {inviter} (ID: {inviter.id})')
                    bot_member = member.guild.get_member(bot.user.id)
                    inviter_member = member.guild.get_member(inviter.id)
                    if bot_member is None:
                        logger.warning('Bot member not found in guild.')
                    if inviter_member is None:
                        logger.warning('Inviter member not found in guild.')
                    else:
                        logger.info(f'Bot top role: {bot_member.top_role} (position {bot_member.top_role.position})')
                        logger.info(f'Inviter top role: {inviter_member.top_role} (position {inviter_member.top_role.position})')
                        if bot_member.top_role.position <= inviter_member.top_role.position:
                            logger.warning('Bot role is not higher than inviter role. Cannot kick.')
                    try:                    
                        await member.guild.ban(member, reason="Bot added to server - banned automatically")
                        logger.info(f'Banned bot {member} from the server.')              
                        await member.guild.ban(inviter, reason="Added a bot to the server - banned automatically")
                        logger.info(f'Banned inviter {inviter} for adding a bot.')
                    except discord.Forbidden:
                        logger.error(f'Failed to ban {inviter} or bot {member}: Missing Permissions')
                    except Exception as e:
                        logger.error(f'Failed to ban {inviter} or bot {member}: {e}')
                    break
        except Exception as e:
            logger.error(f'Error fetching audit logs: {e}')
@bot.event
async def on_raw_reaction_add(payload): #edit nyo lang to
    role_id = 1380187346644766861  # ID ng role na gusto mong i-assign
    message_id = 1380186486162460744  # ID ng message kung saan mo gustong i-check ang reaction
    emoji_to_check = ":orca:  " # Emoji na gusto mong i-check
    if payload.message_id != message_id:
        return
    if not (payload.emoji.name == "orca" and str(payload.emoji.id) == "1380186985053814955"):#custom emoji check
        return
    guild = bot.get_guild(payload.guild_id)
    if guild is None:
        logger.warning(f"Guild not found for ID: {payload.guild_id}")
        return
    role = guild.get_role(role_id)
    if role is None:
        logger.warning(f"Role not found for ID: {role_id}")
        return
    member = guild.get_member(payload.user_id)
    if member is None:
        logger.warning(f"Member not found for ID: {payload.user_id}")
        return
    try:
        await member.add_roles(role)
        logger.info(f"Added role {role.name} to user {member.display_name} for reaction :orca:")
    except discord.Forbidden:
        logger.error(f"Missing permissions to add role {role.name} to user {member.display_name}")
    except Exception as e:
        logger.error(f"Failed to add role {role.name} to user {member.display_name}: {e}")
@bot.command(name='scan')
async def scan(ctx, url: str):
    """Scan a URL using VirusTotal"""
    if not VIRUSTOTAL_API_KEY:
        await ctx.send("VirusTotal API key is not set. Please set it in the .env file.")
        return
    await ctx.send(f"Scanning URL: {url}")
    result = await query_virustotal(url)
    if result:
        stats = result.get("stats", {})
        positives = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = sum([v for v in stats.values() if isinstance(v, int)])
        if positives > 0:
            color = discord.Color.red()
            status_emoji = "🛑"
            status_text = "Malicious detections found!"
        elif suspicious > 0:
            color = discord.Color.orange()
            status_emoji = "⚠️"
            status_text = "Suspicious detections found!"
        else:
            color = discord.Color.green()
            status_emoji = "✅"
            status_text = "No malicious detections."
        embed = discord.Embed(
            title=f"Scan results for {url}",
            description=f"{status_emoji} {status_text}",
            color=color
        )
        embed.add_field(name="Malicious detections", value=f"🛑 {positives}", inline=True)
        embed.add_field(name="Suspicious detections", value=f"⚠️ {suspicious}", inline=True)
        embed.add_field(name="Harmless detections", value=f"✅ {harmless}", inline=True)
        embed.add_field(name="Undetected", value=f"❓ {undetected}", inline=True)
        embed.add_field(name="Total engines", value=f"🔍 {total}", inline=True)
        analysis_id = None
        if isinstance(result, dict) and "analysis_id" in result:
            analysis_id = result["analysis_id"]
        if not analysis_id:
            analysis_id = None
        if analysis_id:
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            detailed_report = requests.get(analysis_url, headers={"x-apikey": VIRUSTOTAL_API_KEY})
            if detailed_report.status_code == 200:
                data = detailed_report.json()
                results = data.get("data", {}).get("attributes", {}).get("results", {})
                details_text = ""
                for engine, result in results.items():
                    category = result.get("category", "unknown")
                    if category not in ["malicious", "suspicious"]:
                        continue
                    method = result.get("method", "unknown")
                    engine_name = result.get("engine_name", engine)
                    result_message = result.get("result", "none")
                    details_text += f"**{engine_name}**: {category} (method: {method}) - Result: {result_message}\n"
                if details_text:
                    if len(details_text) > 1024:
                        details_text = details_text[:1021] + "..."
                    embed.add_field(name="Details", value=details_text, inline=False)
            else:
                embed.add_field(name="Details", value="Failed to retrieve detailed scan results.", inline=False)
        else:
            embed.add_field(name="Details", value="Analysis ID not found, cannot retrieve detailed scan results.", inline=False)
        await ctx.send(embed=embed)
    else:
        await ctx.send("Failed to retrieve scan results from VirusTotal.")

bot.run(TOKEN)
