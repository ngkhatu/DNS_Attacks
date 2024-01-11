/* This file is part of Netwib. Read and honor its license.
*/

/*-------------------------------------------------------------*/
netwib_err netwib_debug_thread_id(netwib_uint32 *pid)
{
#if defined NETWIBDEF_SYSNAME_Unix
  if (pid != NULL) {
    *pid = getpid();
  }
#elif defined NETWIBDEF_SYSNAME_Windows
  if (pid != NULL) {
    *pid = GetCurrentThreadId();
  }
#endif
  return(NETWIB_ERR_OK);
}
