#include <asm/uaccess.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/vmalloc.h>

#define PROCF_NAME "miniFirewall"
#define GET_INIT_MF_RULE_PTR(rule) \
            mf_rule *rule = (mf_rule *)kmalloc(sizeof(mf_rule), GFP_KERNEL); \
            memset(rule, 0, sizeof(mf_rule)); \
            INIT_LIST_HEAD(&(rule->list));

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Linux-simple-firewall");
MODULE_AUTHOR("GGary_TW");

typedef struct mf_rule_struct {
    unsigned int src_ip;
    unsigned int dest_ip;
    int src_port;
    int dest_port;
    int in_out;        // in->1, out->2
    char src_netmask;
    char dest_netmask;
    char proto;                // TCP->1, UDP->2, ALL->3
    char action;               // BLOCK->1, UNBLOCK->2
    struct list_head list;
} mf_rule;

#define SIZE_RULE_WITHOUT_LIST (sizeof(mf_rule) - sizeof(struct list_head))

static mf_rule rule_list;
/* the structure used to register the function (to hook)*/
static struct nf_hook_ops nfho;
static struct nf_hook_ops nfho_out;
static struct proc_dir_entry *mf_proc;

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

/*check the two input IP addresses, see if they match, only the first few bits (masked bits) are compared*/
bool check_ip(unsigned int ip, unsigned int ip_rule, char mask_length)
{
    unsigned int mask = 0;
    int i;
    if (mask_length > 32) {
        printk(KERN_INFO "mask length is illegal\n");
        return false;
    }
    /* if no mask_length set means just block specify ip */
    if (mask_length == 0)
        mask_length = 32;
    for (i=0; i<mask_length; i++) {
        mask |= ((unsigned int)1<<(31-i));
    }
    printk(KERN_INFO "compare ip: %u <=> %u\n", ip, ip_rule);
    printk(KERN_INFO "mask bit length is %d\n", mask_length);
    printk(KERN_INFO "mask = %d\n", mask);
    printk(KERN_INFO "(ip & mask) = %d\n", (ip & mask));
    printk(KERN_INFO "(ip & mask) = %d\n", (ip_rule & mask));

    if ((ip & mask) != (ip_rule & mask)) {
        printk(KERN_INFO "ip compareing doesn't match\n");
        return false;
    }
    return true;
}

void print_a_rule(mf_rule* rule)
{
    char src_ip[16], dest_ip[16];
    ip_hl_to_str(rule->src_ip, src_ip);
    ip_hl_to_str(rule->dest_ip, dest_ip);

    printk(KERN_INFO "in_out: %d\n", rule->in_out);
    printk(KERN_INFO "src_ip: %s\n", src_ip);
    printk(KERN_INFO "src_netmask: %d\n", rule->src_netmask);
    printk(KERN_INFO "src_port: %d\n", rule->src_port);
    printk(KERN_INFO "dest_ip: %s\n", dest_ip);
    printk(KERN_INFO "dest_netmask: %d\n", rule->dest_netmask);
    printk(KERN_INFO "dest_port: %d\n", rule->dest_port);
    printk(KERN_INFO "proto: %d\n", rule->proto);
    printk(KERN_INFO "block: %d\n", rule->action);
}

static void delete_a_rule(unsigned int num)
{
    struct list_head *p, *q;
    mf_rule *a_rule;
    printk(KERN_INFO "delete a rule: %d\n", num);
    list_for_each_safe(p, q, &rule_list.list) {
        num--;
        if (num == 0) {
            a_rule = list_entry(p, mf_rule, list);
            list_del(p);
            kfree(a_rule);
            return;
        }
    }
}

static int check_rule(int in_out, struct sk_buff *skb)
{
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    unsigned int src_ip = ntohl(ip_header->saddr);
    unsigned int dest_ip = ntohl(ip_header->daddr);
    unsigned int src_port = 0;
    unsigned int dest_port = 0;
    struct udphdr *udp_header;
    struct tcphdr *tcp_header;
    char src_ip_str[16], dest_ip_str[16];
    int rule_num = 0;
    mf_rule *a_rule;

    if (ip_header->protocol == 17) {
        udp_header = (struct udphdr *)skb_transport_header(skb);
        src_port = (unsigned int)ntohs(udp_header->source);
        dest_port = (unsigned int)ntohs(udp_header->dest);
    } else if (ip_header->protocol == 6) {
        tcp_header = (struct tcphdr *)skb_transport_header(skb);
        src_port = (unsigned int)ntohs(tcp_header->source);
        dest_port = (unsigned int)ntohs(tcp_header->dest);
    }
    ip_hl_to_str(src_ip, src_ip_str);
    ip_hl_to_str(dest_ip, dest_ip_str);

    if (in_out == 1)
        printk(KERN_INFO "< IN packet info > : \n");
    else
        printk(KERN_INFO "< OUT packet info >: \n");
    printk(KERN_INFO "src ip: %u->%s,   src port: %u", src_ip, src_ip_str, src_port);
    printk(KERN_INFO "dest ip: %u->%s,   dest port: %u", dest_ip, dest_ip_str, dest_port);
    if (ip_header->protocol == 6)
        printk(KERN_INFO "proto: TCP\n");
    else if (ip_header->protocol == 17)
        printk(KERN_INFO "proto: UDP\n");
    else
        printk(KERN_INFO "unknown protocol\n");

    list_for_each_entry(a_rule, &rule_list.list, list) {
        rule_num++;
        printk(KERN_INFO "---------------------------- rule %d check ----------------------------\n", rule_num);
        /* in_out check*/
        if (a_rule->in_out != in_out) {
            printk(KERN_INFO "rule %d (a_rule->in_out: %u) not match: out packet, rule doesn't specify as out\n", rule_num, a_rule->in_out);
            continue;
        }
        /* protocol check*/
        if ((a_rule->proto == 1) && (ip_header->protocol != 6)) {
            printk(KERN_INFO "rule %d not match: rule is TCP, packet is not TCP\n", rule_num);
            continue;
        } else if ((a_rule->proto == 2) && (ip_header->protocol != 17)) {
            printk(KERN_INFO "rule %d not match: rule is UDP, packet is not UDP\n", rule_num);
            continue;
        }
        /* ip check
         * it has three conditions
         * 1. specify ip with it's netmask to block all ip in the net idspecify ip with it's port
         * 2. specify ip without port
         * 3. specify ip with it's port
         * continue 1 has higher pioirity than 3 */
        if (a_rule->src_ip != 0) {
            if (!check_ip(src_ip, a_rule->src_ip, a_rule->src_netmask)) {
                printk(KERN_INFO "rule %d not match: src ip mismatch\n", rule_num);
                continue;
            }
        }
        if (a_rule->dest_ip != 0) {
            if (!check_ip(dest_ip, a_rule->dest_ip, a_rule->dest_netmask)) {
                printk(KERN_INFO "rule %d not match: dest ip mismatch\n", rule_num);
                continue;
            }
        }
        if (a_rule->src_netmask == 0) {
            if (a_rule->src_port != 0) {
                if (src_port != a_rule->src_port) {
                    printk(KERN_INFO "rule %d not match: src port dismatch\n", rule_num);
                    continue;
                }
            }
        }
        if (a_rule->dest_netmask == 0) {
            if (a_rule->dest_port != 0) {
                if (dest_port != a_rule->dest_port) {
                    printk(KERN_INFO "rule %d not match: dest port dismatch\n", rule_num);
                    continue;
                }
            }
        }
        /* block check， if not just log match*/
        if (a_rule->action == 0) {
            printk(KERN_INFO "rule %d match: log match\n", rule_num);
        } else if (a_rule->action == 1) {
            printk(KERN_INFO "rule %d match: block\n", rule_num);
            printk(KERN_INFO "\n");
            return NF_DROP;
        }
    }
    printk(KERN_INFO "\n");
    return NF_ACCEPT;
}

unsigned int hook_func_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    return check_rule(1, skb);
}

unsigned int hook_func_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    return check_rule(2, skb);
}

/* Most read functions return the number of bytes put into the buffer,
   so fread called in user space is same as this return value */
static ssize_t mf_proc_read(struct file *file, char __user *buffer, size_t count, loff_t *f_pos)
{
    int rule_nums_can_copy = count/(sizeof(mf_rule)-sizeof(struct list_head));
    long long int already_copy_to_user = *f_pos;
    long long int entry_pass = already_copy_to_user;
    mf_rule *a_rule;

    printk(KERN_INFO "mf_procf_read (/proc/%s) called\n", PROCF_NAME);
    printk(KERN_INFO "count = %zu\n", count);
    printk(KERN_INFO "f_pos = %lld\n", *f_pos);
    printk(KERN_INFO "----------------------------------------------------------------------\n");

    list_for_each_entry(a_rule, &rule_list.list, list) {
        if (entry_pass != 0) {
            entry_pass--;
            continue;
        }
        copy_to_user((void *)buffer, (const void *)a_rule, SIZE_RULE_WITHOUT_LIST);
        buffer += SIZE_RULE_WITHOUT_LIST;
        *f_pos += 1;
        rule_nums_can_copy--;
        if (rule_nums_can_copy == 0) {
            break;
        }
    }
    return (SIZE_RULE_WITHOUT_LIST * (*f_pos - already_copy_to_user));
}

static ssize_t mf_proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *f_pos)
{
    /* delete count < 24 */
    if (count != 24) {
        unsigned int num = 0;
        copy_from_user((void *)&num, (const void *)buffer, sizeof(unsigned int));
        delete_a_rule(num);
        return count;
    }
    GET_INIT_MF_RULE_PTR(a_rule);
    printk(KERN_INFO "mf_procf_write (/proc/%s) called\n", PROCF_NAME);
    printk(KERN_INFO "count = %zu\n", count);

    if (a_rule == NULL) {
        printk(KERN_INFO "error: cannot allocate memory for a_new_rule\n");
        return 0;
    }
    copy_from_user((void *)a_rule, (const void *)buffer, SIZE_RULE_WITHOUT_LIST);
    list_add_tail(&(a_rule->list), &(rule_list.list));
    printk("User add a rule: \n");
    print_a_rule(a_rule);
    printk(KERN_INFO "----------------------------------------------------------------------\n");
    return count;
}

static struct file_operations mf_ps_op = {
    .owner	= THIS_MODULE,
    .read	= mf_proc_read,
    .write 	= mf_proc_write,
};

int init_module(void)
{
    printk(KERN_INFO "mk_mf: initialize kernel module\n");
    INIT_LIST_HEAD(&(rule_list.list));
    mf_proc = proc_create(PROCF_NAME, 0x0644 ,NULL, &mf_ps_op);
    if (!mf_proc)
        return -ENOMEM;
    /* incoming packet hook */
    nfho.hook = hook_func_in;
    nfho.hooknum = NF_INET_LOCAL_IN;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST; // highest pirority
    nf_register_hook(&nfho);
    /* outgoing packet hook */
    nfho_out.hook = hook_func_out;
    nfho_out.hooknum = NF_INET_LOCAL_OUT;
    nfho_out.pf = PF_INET;
    nfho_out.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho_out);

    return 0;
}

void cleanup_module(void)
{
    struct list_head *p, *q;
    mf_rule *a_rule;

    printk(KERN_INFO "mk_mf: cleanup kernel module\n");
    nf_unregister_hook(&nfho);
    nf_unregister_hook(&nfho_out);
    remove_proc_entry(PROCF_NAME, NULL);
    printk(KERN_INFO "free rule_list\n");
    list_for_each_safe(p, q, &rule_list.list) {
        printk(KERN_INFO "free onen");
        a_rule = list_entry(p, mf_rule, list);
        list_del(p);
        kfree(a_rule);
    }
}
