/*
 * mon_modFile_event.c
 *
 * This program monitors for modifications to a file specified by the user.
 * Event occurrences are printed to the user.  If the file being monitored is
 * removed or renamed, it will be recreated and monitoring will continue.
 *
 * If the filesystem containing the file is unmounted, or the file itself is
 * overmounted, monitoring will cease and the program will exit.
 *
 * This program assumes the AIX Event Infrastructure file system has been
 * mounted on /aha.  To mount it, run:
 *	mkdir /aha
 *	mount -v ahafs /aha /aha
 *
 */

#include <stdio.h>
#include <sys/poll.h>
#include <sys/pollset.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <libgen.h>
#include <usersec.h>
#include <sys/ahafs_evProds.h> 

#define RDWR_BUF_SIZE	4096

int    sequence_num;
char   *objName;
ushort objMode;
uid_t  objUid;
gid_t  objGid;

/* NAME:    skip_lines
 * PURPOSE: Skips a specified number of lines in the buffer passed in.
 * PARAMETERS:
 *	p - Address of the pointer to the head of the buffer
 *	n - The number of lines to skip
 * RETURNS:
 *	Total number of lines skipped
 */
int
skip_lines(char **p, int n)
{
    int lines = 0;

    while(n > 0)
    {
	*p = strchr(*p, '\n');
	if(!p)
	    return(lines);

	(*p)++;
	n--;
	lines++;
    }

    return(lines);
}

/* NAME:    print_op
 * PURPOSE: Prints a string indicating what monitored file operation triggered
 *	    the event occurrence.
 * PARAMETERS:
 *	evp_rc - The return code from RC_FROM_EVPROD
 * RETURNS:
 *	Nothing.
 */
void
print_op(int evp_rc)
{
    if(evp_rc == AHAFS_MODFILE_WRITE)
	printf("File written.");
    else if(evp_rc == AHAFS_MODFILE_UNMOUNT)
	printf("Filesystem unmounted.");
    else if(evp_rc == AHAFS_MODFILE_MAP)
	printf("File mapped.");
    else if(evp_rc == AHAFS_MODFILE_REMOVE)
	printf("File removed.");
    else if(evp_rc == AHAFS_MODFILE_RENAME)
	printf("File renamed.");
    else if(evp_rc == AHAFS_MODFILE_FCLEAR)
	printf("File cleared.");
    else if(evp_rc == AHAFS_MODFILE_FTRUNC)
	printf("File truncated.");
    else if(evp_rc == AHAFS_MODFILE_OVERMOUNT)
	printf("File overmounted.");
    else
	printf("Unknown file op: %d", evp_rc);
}	

/* NAME:    mk_subdirs
 * PURPOSE: Creates necessary subdirectories in the AIX Event Infrastructure
 *	    file system for monitoring the object specified.
 * RETURNS: 
 *	Return code from mkdir call
 */
int
mk_subdirs()
{
    char cmd[2048];
    char *p;

    /* Strip off the monitor file name */
    p = strrchr(objName, '/');

    if(p == NULL)
	return(0);

    sprintf(cmd, "/usr/bin/mkdir -p /aha/fs/modFile.monFactory/");
    strncat(cmd, objName, (p - objName));
    return(system(cmd));
}

/* NAME:    parse_data
 * PURPOSE: This function will parse the event occurrence data and take 
 *	    corrective action if necessary. 
 * PARAMETERS:
 *	buf - A pointer to the buffer containing the event occurrence data
 *	err - Indicates if the previous select() call returned an error
 *	      (a different parsing format is required).
 * RETURNS:
 *	  0 - No corrective action needed.
 *	  1 - Corrective action taken, monitoring must be restarted.
 *	  2 - Unrecoverable error in parsing
 */
int
parse_data(char *buf, int err)
{
    int    rc = 0, evp_rc, recreate = 0;
    char   *p;
    time_t sec, nsec;
    int    seq_num;
    pid_t  pid;
    uid_t  uid, gid;
    gid_t  luid;
    char   curTm[64], cmd[64];
    char   uname[64], lname[64], gname[64];

    p = buf;

    /* Check for BUF_WRAP */
    if(strncmp(buf, "BUF_WRAP", strlen("BUF_WRAP")) == 0)
    {
	printf("Buffer wrap detected, Some event occurrences lost!\n");
	return(0);
    }

    /* Since we are using the default buffer size (4K), and have specified
     * INFO_LVL=1, we won't see any EVENT_OVERFLOW conditions.  Applications
     * should check for this keyword if they are using an INFO_LVL of 2 or
     * higher, and have a buffer size of <= 4K
     */
	
    /* Skip "BEGIN_EVENT_INFO" header */
    if(skip_lines(&p, 1) != 1)
	return(2);

    /* Get timestamp and sequence number. */
    if(sscanf(p,"TIME_tvsec=%ld\nTIME_tvnsec=%ld\nSEQUENCE_NUM=%d\n",
	&sec, &nsec, &seq_num) == 3)
    {
        ctime_r(&sec, curTm);
	if(skip_lines(&p, 3) != 3)
	    return(2);

	printf("Time		: %s", curTm);
	printf("Seq num		: %d", seq_num);
	if(seq_num != sequence_num)
	    printf(" (%d duplicates)\n", (seq_num - sequence_num));
	else
	    printf("\n");

	sequence_num = seq_num + 1;
    }
    else
	return(2);

    if(err)
    {
	/* We just expect to see the RC_FROM_EVPROD and the "END_EVENT_DATA"
	 * footer after the timestamp and sequence number in the error case */
	if(sscanf(p, "RC_FROM_EVPROD=%d\nEND_EVENT_DATA", &evp_rc) == 1)
	{
	    printf("Error in event monitoring: %d.", evp_rc);
	    if(evp_rc == ENODEV)
	    {
		/* Object being monitored doesn't exist, recreate it */
		printf(" Recreating object.\n");
		recreate = 1;
	    }
	    else
	    {
		/* Some other error occurred which we can't correct */
		printf(" Unable to recover.\n");
		rc = 2;
	    }
	}
	else
	    return(2);
    }
    else
    {
	/* Collect user and process info */
	if(sscanf(p, 
		"PID=%ld\nUID=%ld\nUID_LOGIN=%ld\nGID=%ld\nPROG_NAME=%s\n",
                &pid, &uid, &luid, &gid, cmd) == 5)
	{
	    strcpy(uname, IDtouser(uid));
	    strcpy(lname, IDtouser(luid));
	    strcpy(gname, IDtogroup(gid));

	    printf("Process ID	: %d\n", pid);
	    printf("User Info	: userName=%s, loginName=%s, groupName=%s\n",
                       uname, lname, gname);
	    printf("Program Name	: %s\n", cmd);

	    /* Get the RC_FROM_EVPROD */
	    if(skip_lines(&p, 5) != 5)
		return(2);

	    if(sscanf(p, "RC_FROM_EVPROD=%d\nEND_EVENT_DATA", &evp_rc) == 1)
	    {
		print_op(evp_rc);

		switch(evp_rc)
		{
		    case AHAFS_MODFILE_REMOVE:	
		    case AHAFS_MODFILE_RENAME:	
			/* Recreate the object */
			printf(" Recreating object.\n\n");
			recreate = 1;
			break;
		    case AHAFS_MODFILE_OVERMOUNT:
		    case AHAFS_MODFILE_UNMOUNT:
			/* Unrecoverable "unavailable" events. */
			printf(" Unable to recover.\n\n");
			rc = 2;
			break;
		    default:
			printf(" No action required.\n\n");
		}
	    }
	    else
		return(2);
	}
	else
	    return(2);

    }

    if(recreate)
    {
	int fd;
	fd = creat(objName, objMode);
	if(fd != -1)
	{
	    rc = chown(objName, objUid, objGid);
	}

	if((fd == -1) || rc)
	{
	    perror("Error recreating object");
	    rc = 2;
	}
	else
	    rc = 1;
    }

    return(rc);
}

int
main(int argc, char *argv[])
{
    int    c, i = 0;
    int    fd, rc, bytes, err=0, restart;
    fd_set readfds;
    char   monFile[PATH_MAX];
    char   resultData[RDWR_BUF_SIZE];
    char   monFileWrStr[RDWR_BUF_SIZE];
    struct stat statbuf;

    if(argc != 2)
    {
	printf("Usage: %s <full path to file to monitor>\n", argv[0]);
	printf("  Example: %s /etc/passwd\n", argv[0]);
	return(-1);
    }


    /* Create monitor file name for object */
    objName = argv[1];
    sprintf(monFile, "/aha/fs/modFile.monFactory");
    if((strlen(monFile) + strlen(objName) + 5) > PATH_MAX)
    {
	fprintf(stderr, "Error: Cannot monitor object, path name too long\n");
	return(ENAMETOOLONG);
    }

    /* Make the necessary subdirectories for the monitor file */
    if(rc = mk_subdirs())
	return(rc);

    strcat(monFile, objName);
    strcat(monFile, ".mon");

    /* Save off the mode and ownership of monitored object */
    if(stat(objName, &statbuf) < 0)
    {
	perror("Error stating file");
	return(errno);
    }

    objGid = statbuf.st_gid;
    objUid = statbuf.st_uid;
    objMode = statbuf.st_mode;

open:
    restart = 0;
    sequence_num = 0;

    /* Open the monitor file, creating it if necessary */
    fd = open(monFile, O_CREAT|O_RDWR);
    if(fd < 0)
    {
        perror("Error opening monitor file");
        return(errno);
    }

    /* Write out the monitoring specifications.
     * In this case, we are monitoring for a state change event type 
     * (modFile):
     *    CHANGED=YES
     * We will be waiting in select call, rather than a read:
     *    WAIT_TYPE=WAIT_IN_SELECT
     * we only want minimal information:
     *	  INFO_LVL=1
     */
    sprintf(monFileWrStr, "CHANGED=YES;WAIT_TYPE=WAIT_IN_SELECT;INFO_LVL=1");

    rc = write(fd, monFileWrStr, strlen(monFileWrStr)+1);
    if (rc < 0)
    {
        perror("Error writing to monitor file");
        return(errno);
    }

    /* Keep monitoring for event occurrences until stopped */
    while(1)
    {
	/* Initialize the set */
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
	err = 0;

        rc = select(fd+1, &readfds, NULL, NULL, NULL);
        if (rc <= 0)
        {
	    /* All errors in event monitoring will cause select to return
	     * EBADF.  Read to see if any additional data is available.
	     */
            perror("Error issuing select");
	    err = 1;
        } 


	bytes = pread(fd, resultData, RDWR_BUF_SIZE, 0);
	if(bytes < 0)
	    perror("Error reading monitor file");
	else if(bytes == 0)
	    fprintf(stderr, 
		"Error reading monitor file.  No data to be read\n");
	else
	    restart = parse_data(resultData, err);

	if(restart == 2)
	    break;

	if(restart)
	{
	    close(fd);
	    goto open;
	}
    }
    close(fd);
    return(err);
}

