/**************************************************************************
 * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asf_api.c
 *
 * Description: Contains ASF API Library code.
 * *
 * Authors:	Sachin Saxena <b32168@freescale.com>
 */
/* History
 *  Version	Date		Author		Change Description
*/
/******************************************************************************/


/* SYSTEM INCLUDES */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <asftoolkit.h>

#if 1
#define DPRINT(flag, format, args...) { if (api_verbose & (flag))\
					printf(format, ##args); }
#else
#define DPRINT(flag, format, args...)
#endif


/* MODULE GLOBALS and typedefs */
static ASF_uint32_t 		api_verbose;
static int 		hld_fd = -1;

/* FUNCTIONS */
void asf_verbose(ASF_uint32_t verbose)
{
    api_verbose = verbose;
}

/*
  \brief
  Obtain exclusive access to the ASF.

  Opens the ASF configuration device for use by the API.
  Only a single process may have current access to the device.

  If the ASF has previously been configured and the \b asf_close() called a new
  application may use \b asf_open() to obtain access and the existing
  configuration remains in effect.  This allows multiple applications (at
  different times) to manage the ASF configuration.

  \return     Indication of success or error encountered.

  \retval     	0	The function completed successfully.
  \retval	EUSERS	Device in use by another process.
  \retval    	ENODEV	Invalid or non-existant device minor number.
  \retval	EFAULT	Error accessing user memory (internal).
  \retval	E*	Errno values from open(2) and ioctl(2).
*/
int asf_open()
{
	int 			fd = -1;

	DPRINT(1, "API: asf_open\n");

	/* we use temporary file descriptor so that we don't ruin one already
	   in use by trying to open the driver again and getting
	   EUSERS from the driver.
	*/
	fd = open(HLD_MOUNT_PATH, O_RDWR);
	if (fd < 0)
		return errno;

	hld_fd = fd;
	DPRINT(1, "Opened with FD= %d\n", hld_fd);
	return 0;
}

/*!
  \brief
  Give up exclusive access to the ASF.

  Closes the ASF configuration device for use by the API.  Allows another
  process to obtain access to the device.

  Closing the ASF configuration device does not terminate or alter the current
  configuration. The device may be re-open the device using \b asf_close() and
  continue configuration of the ASF.

  \return     Indication of success or error encountered.

  \retval     	0	The function completed successfully.
  \retval	E*	Errno values from close(2).
*/
int asf_close()
{
    int	ret;
    DPRINT(1, "API: asf_close\n");

    ret = close(hld_fd);

    return ret;
}



/*!
  \brief Write LAN VLAN handling configuration.

  \param	lan
  Designates the LAN to which the rules are written.

  Valid values are 0 or 1 corresponding to LAN0 or LAN1.

  \param	vlan
  Pointer to a lan_vlan_t structure which describes the designated LAN's VLAN
  handling for both transmit and receive.

  \return     Indication of success or error encountered.

  \retval     	0	The function completed successfully.
  \retval	EPROTO	Improper state for this function.
  \retval	EFAULT	Invalid user memory adddress.
  \retval	ENOMEM	Unable to allocate memory for internal use.
  \retval	E*	Errno values from ioctl(2).
  \retval     	TBD	Parameter checking error specific return values
*/
int asf_write_lan_vlan(
    ASF_uint8_t	lan,
    lan_vlan_t	*vlan
    )
{
    ioctl_config_lan_vlan_t	lan_vlan;

    DPRINT(1, "API: asf_write_lan_vlan\n");

    lan_vlan.lan = lan;
    lan_vlan.vlan = vlan;

    if (ioctl(hld_fd, HLD_CONFIG_LAN_VLAN, &lan_vlan) < 0)
	return errno;

    return 0;
}
/*!
  \brief Write LAN pause configuration.

  \param	lan
  Designates the LAN to which the rules are written.

  Valid values are 0 or 1 corresponding to LAN0 or LAN1.

  \param pause
  Pointer to a lan_pause_t structure which describes the
  designated LAN's pause configuration for both transmit and receive.

  \return     Indication of success or error encountered.

  \retval     	0	The function completed successfully.
  \retval	EPROTO	Improper state for this function.
  \retval	EFAULT	Invalid user memory adddress.
  \retval	ENOMEM	Unable to allocate memory for internal use.
  \retval	E*	Errno values from ioctl(2).
  \retval     	TBD	Parameter checking error specific return values
*/
int asf_write_lan_pause(
    ASF_uint8_t	lan,
    lan_pause_t	*pause
    )
{
    ioctl_config_lan_pause_t	lan_pause;

    DPRINT(1, "API: asf_write_lan_pause\n");


    lan_pause.lan = lan;
    lan_pause.pause = pause;

    if (ioctl(hld_fd, HLD_CONFIG_LAN_PAUSE, &lan_pause) < 0)
	return errno;

    return 0;
}
/*!
  \brief
  Modify a LAN's filer table.

  Allows writing one or more entries in the
  LAN's filer table. Filer table rules may be written while the
  LAN is operating, however, care must be taken to write the rules
  in a sequence that does not cause the filer to erroneously direct
  or reject packets.

  This function allows multiple rules to be written in non-contiguous
  entries in the filer table. The array of rules reference by
  filer_rules is written to the filer table in the order they are
  found in the array and each rule is placed in the filer table where designated
  by filer_rule[i].index.

  \param	lan
  Designates the LAN to which the rules are written.

  Valid values are 0 or 1 corresponding to LAN0 or LAN1.

  \param	num_rules
  The number of table rules.

  Specifies the number of filer table entries referenced by
  filer_rule which are to be written into the LAN's filer table.
  Maximum value is LAN_NUM_FILER_RULES - 1.

  \param	filer_rule
  Pointer to num_rules array of lan_ftr_t structures.

  Each element of this array contains all the parameters for a single
  filer rule.

  \param	error_index
  Index of invalid element.

  When an error is detected in an element of filer_rules,
  the object of error_index is set to the index of the invalid array element.
  The return value indicates in which array the error was detected.

  \return     	Indication of success or error encountered.

  \retval     	0	The function completed successfully.
  \retval	EPROTO	Improper state for this function.
  \retval	EINVAL	0 num_rules or NULL filer_rule or NULL error_index.
  \retval	EFAULT	Invalid user memory adddress.
  \retval	ENOMEM	Unable to allocate memory for internal use.
  \retval	E*	Errno values from ioctl(2).
  \retval     	TBD	Parameter checking error specific return values
*/
int asf_write_lan_filer(
    ASF_uint8_t	lan,
    ASF_uint32_t	num_rules,
    lan_ftr_t	*filer_rule,
    ASF_uint32_t	*error_index
    )
{
    ioctl_config_lan_filer_t	filer;

    DPRINT(1, "API: asf_write_lan_filer\n");

    if (!num_rules || filer_rule == NULL)
	return EINVAL;

    if (error_index == NULL)
	return EINVAL;

    filer.lan = lan;
    filer.num_rules = num_rules;
    filer.filer_rule = filer_rule;

    if (ioctl(hld_fd, HLD_CONFIG_LAN_FILER, &filer) < 0)
	return errno;

    return 0;
}
/*!
  \brief Write LAN arbitrary field extraction configuration.

  \param	lan
  Designates the LAN to which the arbitraty extraction fields are written.
  Valid values are 0 or 1 corresponding to LAN0 or LAN1.

  \param	field
  Indicates which arbitrary extraction field parameters are to be written.
  Valid values range from 0 to \b AFX_NUM_FIELDS - 1.

  \param 	lan_afx
  Pointer to a filer_afx_t structure which describes the arbitrary field
  extraction used by the LAN's filer with the FT_ARB_PROP property rules.

  \return     Indication of success or error encountered.

  \retval     	0	The function completed successfully.
  \retval	EPROTO	Improper state for this function.
  \retval	EXDEV	Requested configuration of a device not found.
  \retval	EFAULT	Invalid user memory adddress.
  \retval	ENOMEM	Unable to allocate memory for internal use.
  \retval	E*	Errno values from ioctl(2).
  \retval     	TBD	Parameter checking error specific return values
*/
int asf_write_lan_afx(
    ASF_uint8_t	lan,
    ASF_uint8_t	field,
    filer_afx_t	*lan_afx
    )
{
    ioctl_config_lan_afx_t	afx;

    DPRINT(1, "API: asf_write_lan_afx\n");

    afx.lan = lan;
    afx.field = field;
    afx.lan_afx = lan_afx;

    if (ioctl(hld_fd, HLD_CONFIG_LAN_AFX, &afx) < 0)
	return errno;

    return 0;
}
/*!
  \brief Write LAN parser/filer parsing depth.

  \param	lan
  Designates the LAN to which the parse depth applies.
  Valid values are 0 or 1 corresponding to LAN0 or LAN1.

  \param	parse_depth
  Indicates the depth to which the LAN parse/filer will parse incoming packets.

  \return     Indication of success or error encountered.

  \retval     	0	The function completed successfully.
  \retval	EPROTO	Improper state for this function.
  \retval	EXDEV	Requested configuration of a device not found.
  \retval	EFAULT	Invalid user memory adddress.
  \retval	ENOMEM	Unable to allocate memory for internal use.
  \retval	E*	Errno values from ioctl(2).
  \retval     	TBD	Parameter checking error specific return values
*/
int asf_write_lan_parse_depth(
    ASF_uint8_t	lan,
    enum_lpd_t  parse_depth
    )
{
    ioctl_config_lan_parse_depth_t      lpd;

    DPRINT(1, "API: asf_write_lan_parse_depth\n");

    lpd.lan = lan;
    lpd.parse_depth = parse_depth;

    if (ioctl(hld_fd, HLD_CONFIG_LAN_PARSE_DEPTH, &lpd) < 0)
	return errno;

    return 0;
}
/*!
  \brief Write LAN PAD/CRC and CRC_EN configuration.

  \param	lan
  Designates the LAN to which the padding and checksum configuration applies.
  Valid values are 0 or 1 corresponding to LAN0 or LAN1.

  \param	padcrc
  PAD/CRC setting. The default setting is enabled.

  \param        crc
  CRCEN setting.

  \return     Indication of success or error encountered.

  \retval     	0	The function completed successfully.
  \retval	EPROTO	Improper state for this function.
  \retval	EXDEV	Requested configuration of a device not found.
  \retval	EFAULT	Invalid user memory adddress.
  \retval	ENOMEM	Unable to allocate memory for internal use.
  \retval	E*	Errno values from ioctl(2).
  \retval     	TBD	Parameter checking error specific return values
*/
int asf_write_lan_padcrc(
    ASF_uint8_t lan,
    BOOLE padcrc,
    BOOLE crc
    )
{
    ioctl_config_lan_padcrc_t      lpc;

    DPRINT(1, "API: asf_write_lan_padcrc\n");

    lpc.lan = lan;
    lpc.padcrc = padcrc;
    lpc.crc = crc;

    if (ioctl(hld_fd, HLD_CONFIG_LAN_PADCRC, &lpc) < 0)
	return errno;

    return 0;
}
/*!
  \brief
  Enable and, where applicable, start all configured ASF path segments
  in an orderly manner.

  It is not required that the path segments be in a disabled state.
  Any path segments already enabled will remain enabled.

  \return     	Indication of success or error encountered.

  \retval     	0	The function completed successfully.
  \retval	EPROTO	Improper state for this function.
  \retval	E*	Errno values from ioctl(2).
*/
int asf_control_enable()
{
    DPRINT(1, "API: asf_enable : FD = %d\n", hld_fd);

    if (ioctl(hld_fd, HLD_CONTROL_ENABLE, 0) < 0)
	return errno;

    return 0;
}
/*!
  \brief
  Disable all configured ASF path segments in an orderly manner.

  The path segments of the devices in the ASF are disabled beginning with
  path segments delivering traffic to the ASF from external sources and
  proceeding through the path segments to the destinations external to the ASF.

  \param	quiesce_timeout
  The time to wait in \b 1/100 seconds for traffic in progress in the ASF
  to be delivered externally, i.e., for the ASF to reach a quiescent state.
  A value of 0 indicates that the path segments are to be disabled immediately
  without waiting for the segment to become quiescent.
  A value of 0xFF indicates an infinite timeout.

  \param	force
  Indicates whether to force the disabling of the path segments when the
  timeout period expires even if traffic remains in progress.
  Otherwise, the disabling of path segments ceases when any path segment
  fails to reach a quiescent state prior to the timeout.
  If the forcing of disabling is requested and a path segment fails to quiesce a
  error is returned, but disabling continues for all path segments.

  \return	Indication of success or error encountered.

  \retval     	0	The function completed successfully.
  \retval	EPROTO	Improper state for this function.
  \retval	EFAULT	Invalid user memory adddress.
  \retval	E*	Errno values from ioctl(2).
*/
int asf_control_disable(
    ASF_uint8_t	quiesce_timeout,
    BOOLE	force
    )
{
    ioctl_control_disable_t	disable;

    DPRINT(1, "API: asf_disable\n");

    disable.quiesce_timeout = quiesce_timeout;
    disable.force = force;

    if (ioctl(hld_fd, HLD_CONTROL_DISABLE, &disable) < 0)
	return errno;

    return 0;
}
const static struct {
    int		no;
    char 	*name;
    char	*descr;
} err[] = {  { EPERM, 		"EPERM", 	"Operation not permitted" },
  { ENOENT, 		"ENOENT",	"No such file or directory" },
  { ESRCH, 		"ESRCH",	"No such process" },
  { EINTR , 		"EINTR",	"Interrupted system call" },
  { EIO,		"EIO",		"I/O error" },
  { ENXIO,		"ENXIO",	"No such device or address" },
  { E2BIG,		"E2BIG",	"Arg list too long" },
  { ENOEXEC,		"ENOEXEC",	"Exec format error" },
  { EBADF,		"EBADF",	"Bad file number" },
  { ECHILD,		"ECHILD",	"No child processes" },
  { EAGAIN,		"EAGAIN",	"Try again" },
  { ENOMEM,		"ENOMEM",	"Out of memory" },
  { EACCES,		"EACCES",	"Permission denied" },
  { EFAULT,		"EFAULT",	"Bad address" },
  { ENOTBLK,		"ENOTBLK",	"Block device required" },
  { EBUSY,		"EBUSY",	"Device or resource busy" },
  { EEXIST,		"EEXIST",	"File exists" },
  { EXDEV,		"EXDEV",	"Cross-device link" },
  { ENODEV,		"ENODEV",	"No such device" },
  { ENOTDIR,		"ENOTDIR",	"Not a directory" },
  { EISDIR,		"EISDIR",	"Is a directory" },
  { EINVAL,		"EINVAL",	"Invalid argument" },
  { ENFILE,		"ENFILE",	"File table overflow" },
  { EMFILE,		"EMFILE",	"Too many open files" },
  { ENOTTY,		"ENOTTY",	"Not a typewriter" },
  { ETXTBSY,		"ETXTBSY",	"Text file busy" },
  { EFBIG,		"EFBIG",	"File too large" },
  { ENOSPC,		"ENOSPC",	"No space left on device" },
  { ESPIPE,		"ESPIPE",	"Illegal seek" },
  { EROFS,		"EROFS",	"Read-only file system" },
  { EMLINK,		"EMLINK",	"Too many links" },
  { EPIPE,		"EPIPE",	"Broken pipe" },
  { EDOM,		"EDOM",		"Math argument out of domain" },
  { ERANGE,		"ERANGE",	"Math result not in range" },
  { EDEADLK,		"EDEADLK",	"Resource deadlock may occur" },
  { ENAMETOOLONG,	"ENAMETOOLONG",	"File name too long" },
  { ENOLCK,		"ENOLCK",	"No record locks available" },
  { ENOSYS,		"ENOSYS",	"Function not implemented" },
  { ENOTEMPTY,		"ENOTEMPTY",	"Directory not empty" },
  { ELOOP,		"ELOOP",	"Too many symbolic links encountered" },
  { EWOULDBLOCK,	"EWOULDBLOCK",	"Operation would block" },
  { ENOMSG,		"ENOMSG",	"No message of desired type" },
  { EIDRM,		"EIDRM",	"Identifier removed" },
  { ECHRNG,		"ECHRNG",	"Channel number out of range" },
  { EL2NSYNC,		"EL2NSYNC",	"Level 2 not synchronized" },
  { EL3HLT,		"EL3HLT",	"Level 3 halted" },
  { EL3RST,		"EL3RST",	"Level 3 reset" },
  { ELNRNG,		"ELNRNG",	"Link number out of range" },
  { EUNATCH,		"EUNATCH",	"Protocol driver not attached" },
  { ENOCSI,		"ENOCSI",	"No CSI structure available" },
  { EL2HLT,		"EL2HLT",	"Level 2 halted" },
  { EBADE,		"EBADE",	"Invalid exchange" },
  { EBADR,		"EBADR",	"Invalid request descriptor" },
  { EXFULL,		"EXFULL",	"Exchange full" },
  { ENOANO,		"ENOANO",	"No anode" },
  { EBADRQC,		"EBADRQC",	"Invalid request code" },
  { EBADSLT,		"EBADSLT",	"Invalid slot" },
  { EDEADLOCK,		"EDEADLOCK",	"File locking deadlock error" },
  { EBFONT,		"EBFONT",	"Bad font file format" },
  { ENOSTR,		"ENOSTR",	"Device not a stream" },
  { ENODATA,		"ENODATA",	"No data available" },
  { ETIME,		"ETIME",	"Timer expired" },
  { ENOSR,		"ENOSR",	"Out of streams resources" },
  { ENONET,		"ENONET",	"Machine is not on the network" },
  { ENOPKG,		"ENOPKG",	"Package not installed" },
  { EREMOTE,		"EREMOTE",	"Object is remote" },
  { ENOLINK,		"ENOLINK",	"Link has been severed" },
  { EADV,		"EADV",		"Advertise error" },
  { ESRMNT,		"ESRMNT",	"Srmount error" },
  { ECOMM,		"ECOMM",	"Communication error on send" },
  { EPROTO,		"EPROTO",	"Protocol error" },
  { EMULTIHOP,		"EMULTIHOP",	"Multihop attempted" },
  { EDOTDOT,		"EDOTDOT",	"RFS specific error" },
  { EBADMSG,		"EBADMSG",	"Not a data message" },
  { ENOTUNIQ,		"ENOTUNIQ",	"Name not unique on network" },
  { EBADFD,		"EBADFD",	"File descriptor in bad state" },
  { EREMCHG,		"EREMCHG",	"Remote address changed" },
  { ELIBACC,		"ELIBACC",	"Can't access a shared library" },
  { ELIBSCN,		"ELIBSCN",	".lib section in a.out corrupted" },
  { ESTRPIPE,		"ESTRPIPE",	"Streams pipe error" },
  { EUSERS,		"EUSERS",	"Too many users" },
  { ENOTSOCK,		"ENOTSOCK",	"Socket operation on non-socket" },
  { EDESTADDRREQ,	"EDESTADDRREQ",	"Destination address required" },
  { EMSGSIZE,		"EMSGSIZE",	"Message too long" },
  { EPROTOTYPE,		"EPROTOTYPE",	"Protocol wrong type for socket" },
  { ENOPROTOOPT,	"ENOPROTOOPT",	"Protocol not available" },
  { EPROTONOSUPPORT,	"EPROTONOSUPPORT",	"Protocol not supported" },
  { ESOCKTNOSUPPORT,	"ESOCKTNOSUPPORT",	"Socket type not supported" },
  { EOPNOTSUPP,		"EOPNOTSUPP",	"Operation not supported " },
  { EPFNOSUPPORT,	"EPFNOSUPPORT",	"Protocol family not supported" },
  { EAFNOSUPPORT,	"EAFNOSUPPORT",	"Address family not supported " },
  { EADDRINUSE,		"EADDRINUSE",	"Address already in use" },
  { EADDRNOTAVAIL,	"EADDRNOTAVAIL", "Cannot assign requested address" },
  { ENETDOWN,		"ENETDOWN",	"Network is down" },
  { ENETUNREACH,	"ENETUNREACH",	"Network is unreachable" },
  { ENETRESET,		"ENETRESET",	"Network dropped connection as reset" },
  { ECONNABORTED,	"ECONNABORTED",	"Software caused connection abort" },
  { ECONNRESET,		"ECONNRESET",	"Connection reset by peer" },
  { ENOBUFS,		"ENOBUFS",	"No buffer space available" },
  { EISCONN,		"EISCONN",	"Transport endpoint is connected" },
  { ENOTCONN,		"ENOTCONN",	"Transport endpoint is not connected" },
  { ESHUTDOWN,		"ESHUTDOWN",		"Cannot send after transport" },
  { ETOOMANYREFS,	"ETOOMANYREFS",		"Too many references:" },
  { ETIMEDOUT,		"ETIMEDOUT",		"Connection timed out" },
  { ECONNREFUSED,	"ECONNREFUSED",		"Connection refused" },
  { EHOSTDOWN,		"EHOSTDOWN",		"Host is down" },
  { EHOSTUNREACH,	"EHOSTUNREACH",		"No route to host" },
  { EALREADY,		"EALREADY",		"Already in progress" },
  { EINPROGRESS,	"EINPROGRESS",		"Operation now in progress" },
  { ESTALE,		"ESTALE",		"Stale NFS file handle" },
  { EUCLEAN,		"EUCLEAN",		"Structure needs cleaning" },
  { ENOTNAM,		"ENOTNAM",		"Not a XENIX named type file" },
  { ENAVAIL,		"ENAVAIL",		"No semaphores available" },
  { EISNAM,		"EISNAM",		"Is a named type file" },
  { EREMOTEIO,		"EREMOTEIO",		"Remote I/O error" },
  { EDQUOT,		"EDQUOT",		"Quota exceeded" },
  { ENOMEDIUM,		"ENOMEDIUM",		"No medium found" },
  { EMEDIUMTYPE,	"EMEDIUMTYPE",		"Wrong medium type" },
  /* must be Last */
  { 0,			"SUCCESS",		"Successful completion" }
};

/*!
  \brief
  Translates an ASF API library function error return value
  into a short string containg the name of the errno define.
  Additionally, a short description is provided.

  \param	error
  The value returned by an ASF API function.

  \param	description
  A pointer to a short generic description of the error.

  \return     error_name
  A pointer to a string containing the errno define name of error.

  If error does not match a NULL is returned and *description
  is set to "Unrecognized Error".

  This is a pointer to a static string provided in this function
  and should only read (printed) or copied and not altered.
*/
char *asf_error_name(int error, char **description)
{
    int	e;

    for (e = 0; err[e].no != 0; e++)
	if (error == (err[e].no)) {
		*description = err[e].descr;
		return err[e].name;
	}

    /* we didn't find one */
    *description = "Unrecognized Error";
    return NULL;

}

/* To Read / Print Lan Filer table */
int asf_read_lan_filer(ASF_uint8_t lan)
{
	unsigned long lan_num = lan;
	DPRINT(1, "API: asf_read_lan_filer\n");

	if (ioctl(hld_fd, HLD_PRINT_FILER, &lan_num) < 0)
		return errno;

	return 0;
}
/*! \} end Functions */
