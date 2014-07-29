/*
Copyright 2014 Cloudbase Solutions Srl

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#pragma once

//TODO: lookup these msdn docs regarding defining custom error codes:
/*
Using NTSTATUS Values
http://msdn.microsoft.com/en-us/library/windows/hardware/ff565436%28v=vs.85%29.aspx

Defining New NTSTATUS Values
"Drivers cannot use custom NTSTATUS values for IRPs that can be received in user mode, because only the system-defined values can be translated into Win32 error codes."
(oops!)
http://msdn.microsoft.com/en-us/library/windows/hardware/ff543026%28v=vs.85%29.aspx

Defining Custom Error Types
http://msdn.microsoft.com/en-us/library/windows/hardware/ff543017%28v=vs.85%29.aspx
*/

typedef enum _OVS_ERROR
{
    OVS_ERROR_NOERROR = 0,
    // The operation is not permitted
    OVS_ERROR_PERM = ((ULONG)-1),
    // There is no such file or directory
    OVS_ERROR_NOENT = ((ULONG)-2),
    // There is no such process
    OVS_ERROR_SRCH = ((ULONG)-3),
    // An interrupted system call / interrupted function
    OVS_ERROR_INTR = ((ULONG)-4),
    // An I/O error
    OVS_ERROR_IO = ((ULONG)-5),
    // There is no such device or address
    OVS_ERROR_NXIO = ((ULONG)-6),
    // The argument list is too long
    OVS_ERROR_2BIG = ((ULONG)-7),
    // Executable file format error
    OVS_ERROR_NOEXEC = ((ULONG)-8),
    // A bad file descriptor / number
    OVS_ERROR_BADF = ((ULONG)-9),
    // Have no child processes
    OVS_ERROR_CHILD = ((ULONG)-10),
    // resource unavailable => try again later
    OVS_ERROR_AGAIN = ((ULONG)-11),
    // We're out of memory
    OVS_ERROR_NOMEM = ((ULONG)-12),
    // Permission is denied
    OVS_ERROR_ACCES = ((ULONG)-13),
    // A bad address
    OVS_ERROR_FAULT = ((ULONG)-14),

    // The device or the resource is busy
    OVS_ERROR_BUSY = ((ULONG)-16),
    // The file exists
    OVS_ERROR_EXIST = ((ULONG)-17),
    // A cross-device link
    OVS_ERROR_XDEV = ((ULONG)-18),
    // There is no such device
    OVS_ERROR_NODEV = ((ULONG)-19),
    // It is not a directory, nor a symbolic link to a directory.
    OVS_ERROR_NOTDIR = ((ULONG)-20),
    // This is a directory
    OVS_ERROR_ISDIR = ((ULONG)-21),
    // An invalid argument
    OVS_ERROR_INVAL = ((ULONG)-22),
    // There are too many files open in system (i.e. no room for another file descriptor)
    OVS_ERROR_NFILE = ((ULONG)-23),
    // The file descriptor value is too large.
    OVS_ERROR_MFILE = ((ULONG)-24),
    // And Inappropriate I/O control operation. Or, this is not a typewriter
    OVS_ERROR_NOTTY = ((ULONG)-25),

    // The file is too large
    OVS_ERROR_FBIG = ((ULONG)-27),
    // There is no space left on the device
    OVS_ERROR_NOSPC = ((ULONG)-28),
    // This is an invalid seek
    OVS_ERROR_SPIPE = ((ULONG)-29),
    // A read-only file system
    OVS_ERROR_ROFS = ((ULONG)-30),
    // There are too many links
    OVS_ERROR_MLINK = ((ULONG)-31),
    // A broken pipe
    OVS_ERROR_PIPE = ((ULONG)-32),
    // The mathematics argument is out of the domain of the function.
    OVS_ERROR_DOM = ((ULONG)-33),
    // The result is too large / cannot be represented
    OVS_ERROR_RANGE = ((ULONG)-34),
    // A resource deadlock would occur
    OVS_ERROR_DEADLK = ((ULONG)-36),

    // The file name is too long
    OVS_ERROR_NAMETOOLONG = ((ULONG)-38),
    // There are no locks available
    OVS_ERROR_NOLCK = ((ULONG)-39),

    // The function is not implemented / not supported
    OVS_ERROR_NOSYS = ((ULONG)-40),
    // The directory is not empty
    OVS_ERROR_NOTEMPTY = ((ULONG)-41),
    //The byte sequence is illegal
    OVS_ERROR_ILSEQ = ((ULONG)-42),

    OVS_ERROR_STRUNCATE = ((ULONG)-80),

    // The address is already in use
    OVS_ERROR_ADDRINUSE = ((ULONG)-100),
    // The requested address cannot be assigned: is is not available
    OVS_ERROR_ADDRNOTAVAIL = ((ULONG)-101),
    // the address family is not supported by the protocol
    OVS_ERROR_AFNOSUPPORT = ((ULONG)-102),
    // The operation / connection is already in progress
    OVS_ERROR_ALREADY = ((ULONG)-103),
    // The message is bad
    OVS_ERROR_BADMSG = ((ULONG)-104),
    // The operation was canceled
    OVS_ERROR_CANCELED = ((ULONG)-105),
    // The software has caused a connection abort
    OVS_ERROR_CONNABORTED = ((ULONG)-106),
    //The connection was refused
    OVS_ERROR_CONNREFUSED = ((ULONG)-107),
    // The connection was reset by the peer
    OVS_ERROR_CONNRESET = ((ULONG)-108),
    // The destination address is required
    OVS_ERROR_DESTADDRREQ = ((ULONG)-109),
    //The host is unreachable
    OVS_ERROR_HOSTUNREACH = ((ULONG)-110),
    // The identifier was removed
    OVS_ERROR_IDRM = ((ULONG)-111),
    // The operations is in progress
    OVS_ERROR_INPROGRESS = ((ULONG)-112),
    // The socket is already connected
    OVS_ERROR_ISCONN = ((ULONG)-113),
    // There are too many levels of symbolic links.
    OVS_ERROR_LOOP = ((ULONG)-114),
    //The message is too large
    OVS_ERROR_MSGSIZE = ((ULONG)-115),
    // The network is down
    OVS_ERROR_NETDOWN = ((ULONG)-116),
    // The network has dropped connection because of a reset (i.e. the connection was aborted by the network)
    OVS_ERROR_NETRESET = ((ULONG)-117),
    // The network is unreachable
    OVS_ERROR_NETUNREACH = ((ULONG)-118),
    // There is no buffer space available
    OVS_ERROR_NOBUFS = ((ULONG)-119),
    // There is no data available (on the stream head read queue)
    OVS_ERROR_NODATA = ((ULONG)-120),
    // The link has been severed (it's reserved in posix)
    OVS_ERROR_NOLINK = ((ULONG)-121),
    // There is no message of the desired type
    OVS_ERROR_NOMSG = ((ULONG)-122),
    // The protocol is not available
    OVS_ERROR_NOPROTOOPT = ((ULONG)-123),
    // We're out of streams resources
    OVS_ERROR_NOSR = ((ULONG)-124),
    // This is not a stream
    OVS_ERROR_NOSTR = ((ULONG)-125),
    // The socket is not connected
    OVS_ERROR_NOTCONN = ((ULONG)-126),
    // The state is not recoverable
    OVS_ERROR_NOTRECOVERABLE = ((ULONG)-127),
    // This is not a socket
    OVS_ERROR_NOTSOCK = ((ULONG)-128),
    // The operation is not supported
    OVS_ERROR_NOTSUPP = ((ULONG)-129),
    // The operation is not supported on socket
    OVS_ERROR_OPNOTSUPP = ((ULONG)-130),

    OVS_ERROR_OTHER = ((ULONG)-131),
    // The value is too large for the data type
    OVS_ERROR_OVERFLOW = ((ULONG)-132),
    // The previous owner died
    OVS_ERROR_OWNERDEAD = ((ULONG)-133),
    // A protocol error
    OVS_ERROR_PROTO = ((ULONG)-134),
    // The protocol is not supported
    OVS_ERROR_PROTONOSUPPORT = ((ULONG)-135),
    // This is a wrong protocol type for the socket
    OVS_ERROR_PROTOTYPE = ((ULONG)-136),
    // The timer has expired (or, the stream ioctl has timed out)
    OVS_ERROR_TIME = ((ULONG)-137),
    // The connection has timed out
    OVS_ERROR_TIMEDOUT = ((ULONG)-138),
    // The given text file is busy
    OVS_ERROR_TXTBSY = ((ULONG)-139),
    //the operation would block
    OVS_ERROR_WOULDBLOCK = ((ULONG)-140),
} OVS_ERROR;