#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GET_INIT_MF_RULE(rule)     \
            mf_rule rule = {       \
                .src_ip = 0,     \
                .dest_ip = 0,    \
                .src_port = 0,     \
                .dest_port = 0,    \
                .in_out = 0,       \
                .src_netmask = 0,  \
                .dest_netmask = 0, \
                .proto = 0,        \
                .action = 0        \
            }


typedef struct mf_rule_struct {
    unsigned int src_ip;
    unsigned int dest_ip;
    unsigned int src_port;
    unsigned int dest_port;
    int in_out;        // in->1, out->2
    char src_netmask;
    char dest_netmask;
    char proto;                // TCP->1, UDP->2, ALL->3
    char action;               // LOG->0， BLOCK->1
} mf_rule;

unsigned int ip_str_to_hl(char *ip_str)
{
    unsigned int ip_array[4];
    unsigned int ip = 0;
    if (ip_str==NULL) {
        return 0;
    }
    sscanf(ip_str, "%u.%u.%u.%u", ip_array, ip_array+1, ip_array+2, ip_array+3);
    for (int i=0; i<4; i++) {
        assert((ip_array[i] <= 255) && "Wrong ip format");
    }
    ip = (ip_array[0] << 24);
    ip = (ip | (ip_array[1] << 16));
    ip = (ip | (ip_array[2] << 8));
    ip = (ip | ip_array[3]);
    return ip;
}

void ip_hl_to_str(unsigned int ip, char *ip_str)
{
    /*convert hl to byte array first*/
    unsigned char ip_array[4];
    memset(ip_array, 0, 4);
    ip_array[0] = (ip_array[0] | (ip >> 24));
    ip_array[1] = (ip_array[1] | (ip >> 16));
    ip_array[2] = (ip_array[2] | (ip >> 8));
    ip_array[3] = (ip_array[3] | ip);
    sprintf(ip_str, "%u.%u.%u.%u", ip_array[0], ip_array[1], ip_array[2], ip_array[3]);
}

void send_rule(const mf_rule *rule)
{
    FILE *fp;
    fp = fopen("/proc/miniFirewall", "w");
    if (fp == NULL) {
        perror("fopen");
        exit(1);
    } else {
        fwrite(rule, sizeof(mf_rule), 1, fp);
    }
    fclose(fp);
}

void delete_rule(unsigned int num)
{
    FILE *fp;
    fp = fopen("/proc/miniFirewall", "w");
    if (fp == NULL) {
        perror("fopen");
        exit(1);
    } else {
        fwrite(&num, sizeof(unsigned int), 1, fp);
    }
    fclose(fp);
}

void print_a_rule(mf_rule* rule)
{
    char src_ip[16], dest_ip[16];
    ip_hl_to_str(rule->src_ip, src_ip);
    ip_hl_to_str(rule->dest_ip, dest_ip);

    printf("in_out: %d\n", rule->in_out);
    printf("src_ip: %u->%s\n", rule->src_ip, src_ip);
    printf("src_netmask: %d\n", rule->src_netmask);
    printf("src_port: %d\n", rule->src_port);
    printf("dest_ip: %u->%s\n", rule->dest_ip, dest_ip);
    printf("dest_netmask: %d\n", rule->dest_netmask);
    printf("dest_port: %d\n", rule->dest_port);
    printf("proto: %d\n", rule->proto);
    printf("action: %d\n", rule->action);
}

void print_rule()
{
    FILE *fp;
    int count = 1;
    mf_rule a_rule;

    fp = fopen("/proc/miniFirewall", "r");
    if (fp == NULL) {
        perror("fopen");
        exit(1);
    }
    while (fread(&a_rule, sizeof(mf_rule), 1, fp) > 0) {
        printf("--------------------------------rule%d--------------------------------\n", count++);
        print_a_rule(&a_rule);
        putchar('\n');
    }
}

void rule_init(mf_rule* rule)
{
    rule->in_out = 0;
    rule->src_netmask = 0;
    rule->src_port = 0;
    rule->dest_netmask = 0;
    rule->dest_port = 0;
    rule->proto = 0;
    rule->action = 0;
}

void usage() {
    printf("\nUsage:\n");
    printf("mf [-a <action>] [-c <protocol>] [-d <rule_number>] [-h] [--in] [-m <src_netmask>]\n");
    printf("[-n <dest_netmask>] [--out] [-o] [-p <src_port>] [-q <dest_port>] [-s <src_ip>] [-\n");
    printf("t <dest_ip>]\n\n");
    printf(" -a <action>\n");
    printf("       Specify rule action. Only BLOCK or LOG.\n\n");
    printf(" -c <protocol>\n");
    printf("       Specify which protocol of packet to operate. 1 means TCP packet, 2 \n");
    printf("       means UDP packet, and 3 means both.\n\n");
    printf(" -d <rule_number>\n");
    printf("       Delete a specified rule. The rule number can get by option [-o].\n\n");
    printf(" -h\n");
    printf("       Print usage of mf.\n\n");
    printf(" --in\n");
    printf("       Specify the in-packet to operate.\n\n");
    printf(" -m <src_netmask>\n");
    printf("       Specify netmask length of src packet to operate. (i.e. 24 means netmask\n");
    printf("       ff ff ff 00)\n\n");
    printf(" -n <dest_netmask>\n");
    printf("       Specify netmask length of dest packet to operate.\n\n");
    printf(" --out\n");
    printf("       Specify the out-packet to operate.\n\n");
    printf(" -o\n");
    printf("       Print the specified rules.\n\n");
    printf(" -p <src_port>\n");
    printf("       Specify port of src packet to operate.\n\n");
    printf(" -q <dest_port>\n");
    printf("       Specify port of dest packet to operate.\n\n");
    printf(" -s <src_ip>\n");
    printf("       Specify ip of src packet to operate.\n\n");
    printf(" -t <dest_ip>\n");
    printf("       Specify ip of dest packet to operate.\n\n");
    printf("Example: sudo ./mf -a BLOCK --in -t 31.13.87.36 -n 24\n");
}

int main(int argc, char *const argv[])
{
    GET_INIT_MF_RULE(rule);
    rule_init(&rule);

    char *short_options = "hod:s:m:p:t:n:q:c:a:";
    struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"print", no_argument, NULL, 'o'},
        {"delete", required_argument, NULL, 'd'},
        {"srcip", required_argument, NULL, 's'},
        {"srcnetmask", required_argument, NULL, 'm'},
        {"srcport", required_argument, NULL, 'p'},
        {"destip", required_argument, NULL, 't'},
        {"destnetmask", required_argument, NULL, 'n'},
        {"destport", required_argument, NULL, 'q'},
        {"proto", required_argument, NULL, 'c'},
        {"action", required_argument, NULL, 'a'},
        {"in", no_argument, &(rule.in_out), 1},
        {"out", no_argument, &(rule.in_out), 2},
        {NULL, 0, NULL, 0}
    };

    int c = 0, action = 1, delete_num = 0;
    while (1) {
        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1)
            break;

        switch (c) {
            case 0:
                /* Flag is automatically set */
                break;
            case 'h':
                usage();
                exit(EXIT_SUCCESS);
            case 'o':
                action = 2;
                break;
            case 'd':
                action = 3;
                delete_num = (unsigned int)atoi(optarg);
                break;
            case 's':
                rule.src_ip =  ip_str_to_hl(optarg);
                break;
            case 'm':
                rule.src_netmask = (char)atoi(optarg);
                break;
            case 'p':
                rule.src_port = (unsigned int)atoi(optarg);
                break;
            case 't':
                rule.dest_ip =  ip_str_to_hl(optarg);
                break;
            case 'n':
                rule.dest_netmask = (char)atoi(optarg);
                break;
            case 'q':
                rule.dest_port = (unsigned int)atoi(optarg);
                break;
            case 'c':
                rule.proto = (char)atoi(optarg);
                break;
            case 'a':
                if (strcmp(optarg, "LOG") == 0) {
                    rule.action = 0;
                } else if (strcmp(optarg, "BLOCK") == 0) {
                    rule.action = 1;
                }
                break;
            case '?':
                /* getopt_long printed an error message. */
                exit(1);
                break;
            default:
                exit(1);
        }
    }
    if (optind < argc) {
        printf("non-option ARGV-elements: ");
        while (optind < argc)
            printf("%s ", argv[optind++]);
        putchar('\n');
        exit(1);
    }

    if (action == 1) {
#ifdef DEBUG
        printf("send_rule\n");
        print_a_rule(&rule);
#endif
        send_rule(&rule);
    } else if (action == 2) {
        print_rule();
    } else {
#ifdef DEBUG
        printf("delete_rule\n");
        print_a_rule(&rule);
#endif
        delete_rule(delete_num);
    }
}

