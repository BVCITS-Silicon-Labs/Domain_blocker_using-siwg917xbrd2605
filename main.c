#include "sl_main_init.h"
#include "sl_main_kernel.h"
#include "app.h"

int main(void)
{
    sl_main_second_stage_init();

    app_init();

    while (sl_main_start_task_should_continue()) {
        app_process_action();
    }

    return 0;
}