#include <stdio.h>
#include <stdlib.h>

struct list {
    char value;
    struct list* next;
};

struct list * unwind() {

    struct list *myStruct = NULL; // var_C
    
    int i = 0; // var_8
    while (i <= 9) {

        struct list *tmp = malloc(8); // var_4
        if (tmp == NULL) {
            exit(1);
        }

        if (myStruct == NULL) {
            myStruct = tmp;
        } else {
            tmp->next = myStruct;
            myStruct = tmp;
        }

        tmp->next = NULL;
        tmp->value = i + 'A';
        i++;
    }

    return myStruct;
}

int main(void) {
    unwind();
    return 0;
}
