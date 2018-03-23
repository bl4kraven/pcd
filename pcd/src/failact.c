/*
 * failact.c
 * Description:
 * PCD failure action implementation file
 *
 * Copyright (C) 2010 Texas Instruments Incorporated - http://www.ti.com/
 *
 * This application is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

/* Author:
 * Hai Shalom, hai@rt-embedded.com 
 *
 * PCD Homepage: http://www.rt-embedded.com/pcd/
 * PCD Project at SourceForge: http://sourceforge.net/projects/pcd/
 *  
 */

/**************************************************************************/
/*      INCLUDES                                                          */
/**************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "system_types.h"
#include "failact.h"
#include "rulestate.h"
#include "ruleid.h"
#include "rules_db.h"
#include "process.h"
#include "except.h"
#include "pcd.h"

/**************************************************************************/
/*      LOCAL DEFINITIONS AND VARIABLES                                   */
/**************************************************************************/

#define PCD_FAILURE_ACTION_KEYWORD( keyword ) \
    PCD_FAILURE_ACTION_FUNCTION( keyword ),

/* Function prototypes */
static const failActionFunc failureActionFuncTable[] =
{
    PCD_FAILURE_ACTION_KEYWORDS
    NULL,
};

#undef PCD_END_COND_KEYWORD

/**************************************************************************/
/*      IMPLEMENTATION                                                    */
/**************************************************************************/

failActionFunc PCD_failure_action_get_function( failureAction_e cond )
{
    return failureActionFuncTable[ cond ];
}

rule_t *PCD_failure_action_NONE( rule_t *rule )
{
    pcdLogState_e logState = PCD_LOGSTATUS_NONE;
    u_int32_t count = (rule->faulty!=-1? 0 :(rule->fail_count>2?2:rule->fail_count));

    switch (rule->ruleState )
    {
    case PCD_RULE_FAILED:
    	logState = PCD_LOGSTATUS_FAILED;
    	break;
    case PCD_RULE_NOT_COMPLETED:
    	logState = PCD_LOGSTATUS_FAULTY;
    	break;
    case PCD_RULE_HUNG:
    	logState = PCD_LOGSTATUS_HUNG;
    	break;
    }

    PCD_PRINTF_INFO_LOGFILE( "Status:%d\nModuleID:%s_%s\nDo nothing %s",logState,rule->failureAction[count].ruleId.groupName, rule->failureAction[count].ruleId.ruleName, (rule->faulty != -1? "because too many fault":"") );

    //In order to run what is after
    rule->ruleState = PCD_RULE_COMPLETED;
    rule->fail_count = 0;
    rule->fail_reset = 0;
    //rule->starttime = 0;

    return NULL;
}

rule_t *PCD_failure_action_REBOOT( rule_t *rule )
{
    pcdLogState_e logState = PCD_LOGSTATUS_NONE;
    u_int32_t count = (rule->faulty!=-1? 0 :(rule->fail_count>2?2:rule->fail_count));

    switch (rule->ruleState )
    {
    case PCD_RULE_FAILED:
    	logState = PCD_LOGSTATUS_FAILED;
    	break;
    case PCD_RULE_NOT_COMPLETED:
    	logState = PCD_LOGSTATUS_FAULTY;
    	break;
    case PCD_RULE_HUNG:
    	logState = PCD_LOGSTATUS_HUNG;
    	break;
    }

    /* Check for exceptions before rebooting */
    PCD_exception_listen();

    PCD_PRINTF_INFO_LOGFILE( "Status:%d\nModuleID:%s_%s\nReboot System",logState,rule->failureAction[count].ruleId.groupName, rule->failureAction[count].ruleId.ruleName );

    /* Reboot the system; Initiate termination sigal to PCD */
    kill( getpid(), SIGTERM );
    return NULL;
}

rule_t *PCD_action_RESTART( rule_t *rule )
{
    u_int32_t count = 0;

    if ( !rule )
    {
        return NULL;
    }

    count = (rule->faulty!=-1? 0 :(rule->fail_count>2?2:rule->fail_count));
    PCD_PRINTF_INFO_LOGFILE( "Status:%d\nModuleID:%s_%s\nStart/Restart", PCD_LOGSTATUS_RESTART, rule->failureAction[count].ruleId.groupName, rule->failureAction[count].ruleId.ruleName );

    /* If a process exists, kill it first */
    if ( rule->proc )
    {
        PCD_process_stop( rule, True, NULL );
    }

    /* Reenqueue rule */
    return( rule );
}

rule_t *PCD_failure_action_RESTART( rule_t *rule )
{
    u_int32_t count = 0;
    pcdLogState_e logState = PCD_LOGSTATUS_NONE;

    if ( !rule )
    {
        return NULL;
    }

    switch (rule->ruleState )
    {
    case PCD_RULE_FAILED:
    	logState = PCD_LOGSTATUS_FAILED;
    	break;
    case PCD_RULE_NOT_COMPLETED:
    	logState = PCD_LOGSTATUS_FAULTY;
    	break;
    case PCD_RULE_HUNG:
    	logState = PCD_LOGSTATUS_HUNG;
    	break;
    }

    count = (rule->faulty!=-1? 0 :(rule->fail_count>2?2:rule->fail_count));
    PCD_PRINTF_INFO_LOGFILE( "Status:%d\nModuleID:%s_%s\nStart/Restart Status", logState, rule->failureAction[count].ruleId.groupName, rule->failureAction[count].ruleId.ruleName );

    if ( rule->fail_reset_count != 0
    		|| rule->faulty != -1 )
    {
    	rule->fail_count++;
    	//rule->starttime = rule->fail_interval * 1000;
    }

    if ( rule->faulty != -1 )
    {
    	if ( rule->fail_count > rule->faulty )
    	{
    		return PCD_failure_action_NONE( rule );
    	}
    }

    /* Reenqueue rule */
    return PCD_action_RESTART( rule );
}

rule_t *PCD_failure_action_EXEC_RULE( rule_t *rule )
{
    rule_t *execRule;
    pcdLogState_e logState = PCD_LOGSTATUS_NONE;
    u_int32_t count = (rule->faulty!=-1? 0 :(rule->fail_count>2?2:rule->fail_count));

    /* Find rule to execute */
    execRule = PCD_rulesdb_get_rule_by_id( &rule->failureAction[count].ruleId );

    switch (rule->ruleState )
    {
    case PCD_RULE_FAILED:
    	logState = PCD_LOGSTATUS_FAILED;
    	break;
    case PCD_RULE_NOT_COMPLETED:
    	logState = PCD_LOGSTATUS_FAULTY;
    	break;
    case PCD_RULE_HUNG:
    	logState = PCD_LOGSTATUS_HUNG;
    	break;
    }

    PCD_PRINTF_INFO_LOGFILE( "Status:%d\nModuleID:%s_%s\nExecute rule",logState,rule->failureAction[count].ruleId.groupName, rule->failureAction[count].ruleId.ruleName );

    //reset current rule
    rule->fail_count = 0;
    rule->fail_reset = 0;
    //rule->starttime = 0;

    if ( !execRule )
    {
        PCD_PRINTF_STDERR( "Failed to execute rule %s_%s, rule not found!", rule->failureAction[count].ruleId.groupName, rule->failureAction[count].ruleId.ruleName );
        return NULL;
    }

    /* Check if rule is already running */
    if ( PCD_RULE_ACTIVE( execRule ) )
    {
        PCD_PRINTF_STDERR( "Failed to execute rule %s_%s, rule already running!", rule->failureAction[count].ruleId.groupName, rule->failureAction[count].ruleId.ruleName );
        return NULL;
    }

    return PCD_action_RESTART( execRule );
}
