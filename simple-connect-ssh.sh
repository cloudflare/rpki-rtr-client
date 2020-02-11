:

#
# FYI type password at prompt - the username/password as per RFC8210 is rpki/rpki
#

HOST="rtr.rpki.cloudflare.com"
PORT="8283"

# -N      Do not execute a remote command.  This is useful for just forwarding ports.
# -T      Disable pseudo-terminal allocation.

exec ssh \
	-N \
	-T \
	-o StrictHostKeyChecking=Yes \
	-o PasswordAuthentication=Yes \
	-o PreferredAuthentications=password \
	-l rpki \
	-p ${PORT} \
	${HOST}

