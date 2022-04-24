#include <math.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
# include <assert.h>
#include <string.h>
#include <openssl/sha.h>




int is_prime_naive(long p){
    int i=3;
    
    while(i<sqrt(p-1)){
        if(p%i!= 0){
            i+=2;
        }
        else{
            return 0;
        }
    }
    return 1;


}
long modpow_naive(long a, long m, long n){
    long i=0;
    long res=1;
    while(i<m){
        res=(a*res)%n;
        i++;
    }
    return res;
}


long modpow(long a ,long m,long n){


    if (m==0) {
        return 1;
    }
    
    if (m%2==0){
        long res=modpow(a,m/2,n);
        return (res*res)%n;
    }
    else{
        long res=modpow(a,(m-1)/2,n);
       return((res*res)*(a))%n;
    }
}
int witness( long a , long b , long d , long p ) {
    long x = modpow (a ,d , p ) ;
    if ( x == 1) {
        return 0;
    }
    for (long i = 0; i < b ; i ++) {
        if ( x == p -1) {
    return 0;
        }
    x = modpow(x ,2 , p ) ;
    }
    return 1;
}

long rand_long( long low , long up ) {

    return rand () %( up -low +1) + low ;
}

int is_prime_miller( long p , int k ) {

    if ( p == 2) {
        return 1;
    }
    if (!( p & 1) || p <= 1) { //on verifie que p est impair et different de 1
        return 0;
    }
    //on determine b et d :
    long b = 0;
    long d = p - 1;
    while (!( d & 1) ) { //tant que d n'est pas impair
        d = d /2;
        b = b +1;
    }
    // On genere k valeurs pour a, et on teste si c’est un temoin :
    long a ;
    int i ;
    for ( i = 0; i < k ; i ++) {
        a = rand_long (2 , p -1) ;
        if ( witness(a ,b ,d , p ) ) {
            return 0;
        }
    }
    return 1;

}
long power(long a,long b){
    long res=1;
    for(long i=0;i<b;i++){
        res=res*a;

    }
    return res;
}

long random_prime_number(int low_size,int up_size,int k){
    long low=power(2,low_size-1);
    long up=power(2,up_size)-1;
    //printf("%ld %ld \n", low, up);


    long p=rand_long(low ,up );
    
    if( is_prime_miller(p, k)==1){
       // printf("p=%ld\n",p);
        return p;
    }
    else{
        return random_prime_number(low_size,up_size,k);
    }


}
//=========---Ex2--==========

long extended_gcd(long s, long t, long *u, long *v){
    if (s==0){
        *u = 0;
        *v = 1;
        return t;
    }
    long uPrim, vPrim;
    
    long gcd = extended_gcd(t%s, s, &uPrim, &vPrim);
    
   
    *u = vPrim - ((t/s)*uPrim);
    *v = uPrim;

    return gcd;
}


void generate_keys_values(long p, long q, long* n, long *s, long *u){

    *n = p*q;
    long t = (p-1)*(q-1);
    long v=1;
   
    while (extended_gcd(*s, t, u, &v) != 1 ) {
        *s = rand_long(0,t-1); //random number between 1 and t
        }
   ;
    
}



long* encrypt(char* chaine, long s, long n){
    long* nouvCh = (long*)malloc(sizeof(long)*strlen(chaine));

    for (int i=0; i <strlen(chaine); i++){

        nouvCh[i] = modpow((long)chaine[i], s, n);
        //printf("%ld ",nouvCh[i]);

    }
    printf("\n");
    return nouvCh; //long*
}

char* decrypt(long* crypted, int size, long u, long n){
 
    char * decrpt = (char*)malloc(sizeof(char)*(size+1));
    
    for (int i = 0; i<size; i++){
        //printf("%ld ",modpow(crypted[i], u,n));
        decrpt[i]=(char)modpow(crypted[i], u,n);

    }
    decrpt[size]='\0';
    return decrpt; // char*
}

//======-Execution-=======

void print_long_vector ( long * result , int size ) {
    printf ("Vector : [");
    for (int i =0; i < size ; i ++) {
        printf ("%ld\t ", result [ i ]) ;
    }
    printf ("]\n");
}

//============-PARTIE_2-=============s
typedef struct key{
  long value;
  long n;
}Key;

void init_key(Key* key, long val, long n){
    key->value = val;
    key->n =n;
    return;
}

void init_pair_keys(Key* pKey, Key* sKey, long low_size, long up_size){

    long p = random_prime_number (low_size, up_size, 5000);
    long q = random_prime_number (low_size, up_size, 5000) ;
    while ( p == q ) {q = random_prime_number (low_size, up_size, 5000);}
    long n , s , u ;

    generate_keys_values(p, q, &n, &s, &u) ;
    //Pour avoir des cles positives :
    if (u <0) {
    long t = (p -1) *( q -1) ;
    u = u + t ; //on aura toujours s*u mod t = 1
    }

    init_key(pKey, s, n);
    init_key(sKey, u, n);
}

char* key_to_str(Key* key){
    char * str = malloc(sizeof(char)*sizeof(Key));
    sprintf(str, "(%lx,%lx)", key->value, key->n);
    return str;
}

Key* str_to_key(char* str){
    long value, n;
    Key *key = malloc(sizeof(Key));
    sscanf(str, "(%lx,%lx)", &value, &n);

    init_key(key, value, n);
    return key;
}

typedef struct signature{
  long *content;
  int size;
}Signature;

Signature* init_signature(long* content ,int size){
  
    Signature *tab=(Signature*)malloc(sizeof(Signature));

     tab->content=content;
    
    
    tab->size=size;
    return tab;

}


Signature *sign(char *mess ,Key *sKey){
    long * ini=encrypt(mess,sKey->value, sKey->n);

   return init_signature(ini,strlen(mess));
    free(ini);
}
char * signature_to_str ( Signature * sgn ) {

    char * result = malloc (10*sgn -> size * sizeof ( char ) ) ;
        result[0]= '#' ;
        int pos = 1;
        char buffer[156];
        for (int i =0; i < sgn -> size ; i ++) {
        sprintf ( buffer , "%lx", sgn -> content [ i ]) ;
        for (int j =0; j < strlen ( buffer ) ; j ++) {
        result[ pos ] = buffer [ j ];
        pos = pos +1;
        }
        result[ pos ] = '#' ;
        pos = pos +1;
        }
        result[ pos ] = '\0' ;
        result = realloc ( result , ( pos +1) * sizeof ( char ) ) ;
        return result ;
}

Signature * str_to_signature ( char * str ) {
        int len = strlen ( str ) ;
        long * content = ( long *) malloc ( sizeof ( long ) * len ) ;
        int num = 0;
        char buffer[256];
        int pos = 0;
            for (int i =0; i < len ; i ++) {
                if ( str[ i ] != '#') {
                buffer[ pos ] = str[ i ];
                pos = pos +1;
            } else {
                if ( pos != 0) {
                buffer[ pos ] = '\0';
                sscanf ( buffer , "%lx", &( content[ num ]) ) ;
                num = num + 1;
                pos = 0;
                }
            }
            }
            content = realloc (content, num * sizeof ( long ) ) ;

    return init_signature ( content , num ) ;
 }

typedef struct protected{
  Key *pKey; 
  char *mess;
  Signature *sgn;
}Protected;

Protected *init_protected(Key *pKey,char *mess,Signature *sgn_is){
     
    Protected *pro=(Protected *)malloc(sizeof(Protected));
    
   pro->pKey = pKey;
    pro->mess=strdup(mess);
    pro->sgn=sgn_is;

    return pro;

}

int verify(Protected *pr){
       long * crypted = pr->sgn->content;
        int size = pr->sgn->size;
        long u = pr->pKey->value;
        long n = pr->pKey->n;
        char * decrpt = decrypt(crypted, size, u, n);
    
        char * messg = pr->mess;

        if(strcmp(decrpt, messg)==0){
           // free(de)
            return 1;
        }
        else{
            return 0;
        }

    }


char* protected_to_str(Protected *pr){

    char* str=(char*)malloc(sizeof(char)*10);
    char * key = key_to_str(pr->pKey);
    char * mess = pr->mess;
    char * sgn = signature_to_str(pr->sgn);
  

    sprintf(str,"%s""\t%s""\t%s", key,mess, sgn);

    return str;
}

Protected *str_to_protected(char *str){
     
    char mess[60];
    char key[60];
  char sgn[60];

    sscanf(str,"%s""\t%s""\t%s",key,mess,sgn);
return init_protected(str_to_key(key),mess,str_to_signature(sgn));

}


void generate_random_data(int nv,int nc){

    FILE *keys=fopen("keys.txt","w");
    FILE *candidates=fopen("candidates.txt","w");
    FILE *declarations=fopen("declarations.txt","w");
    //FILE *f1=fopen("declar.txt","w");

    if(keys==NULL || candidates==NULL || declarations==NULL){
        printf("erreur lors de l'allocation");
        return ;
    }

    Key *pKey=(Key*)malloc(sizeof(Key));
    Key *sKey=(Key*)malloc(sizeof(Key));
    //Key *pKeyC=(Key*)malloc(sizeof(Key));
    //Key *sKeyC=(Key*)malloc(sizeof(Key));


    if(pKey==NULL || sKey==NULL) {
        printf("Erreur lors de l'allocation");
        return ;
    }

    for(int i=0;i<nv;i++){
        init_pair_keys(pKey,sKey, 3,7);
        fprintf(keys,"%s %s\n",key_to_str(pKey),key_to_str(sKey));
    }
    for(int j=0;j<nc;j++){
        init_pair_keys(pKey,sKey,3,7);
        fprintf(declarations,"%s\n",key_to_str(pKey));
    }


    Signature *sgn;
    Protected *pr;
    char bufferV[50];
    char bufferC[25];
    char pKeyChar[25];
    char sKeyChar[25];
    char mess[25];

    rewind(keys);
    rewind(candidates);

    while(fgets(bufferV, 50, keys)){  // the buffer is empty :(
        sscanf(bufferV,"%s""\t%s",pKeyChar,sKeyChar);
        pKey = str_to_key(pKeyChar);
        sKey = str_to_key(sKeyChar);

        rewind(candidates);
        int r = rand() % nc;

        for(int k; k<=r; k++){
            fgets(bufferC, 50, candidates);
            printf("%s\n", bufferC);
        }
        sscanf(bufferC,"%s", mess);

        sgn = sign(mess, sKey);
        pr = init_protected(pKey, mess, sgn);

        fprintf(declarations,"%s\n",protected_to_str(pr));

    }

    free(pKey);
    free(sKey);
   // free(pr->pKey);
   // free(pr->sgn);
    free(pr);
    free(sgn);

    fclose(keys);
    fclose(candidates);
    fclose(declarations);
}

typedef struct cellKey{
    Key *data;
    struct cellKey* next;

}CellKey;

CellKey* create_cell_key(Key* key){
    CellKey *cell=(CellKey*)malloc(sizeof(CellKey));
    cell->data=key;

    cell->next=NULL;
    return cell;
}

void cell_en_tete(CellKey** cell ,Key *data){
    
     CellKey *c=create_cell_key(data);
     c->next=*cell;

     *cell=c;

}



void print_list_keys(CellKey *LCK){

    if(!LCK){
        printf("pas de liste\n");
        return ;
    }
    printf("debut affichage d'une liste de cle\n");
   
    
    while(LCK){
       if(LCK->data!= NULL)
            printf(" %s\n",key_to_str(LCK->data));
        LCK=(LCK)->next;
    }
    printf("fin affichage d'une liste de cle\n");
    return ;


}


CellKey* read_public_keys(char *nomF){
    FILE *f =fopen(nomF,"r");
    if(f==NULL){
        printf("erreur");
        exit(1);
    }

    CellKey *listC=(CellKey*)malloc(sizeof(CellKey));
    char buffer[250];
    
    while(fgets(buffer,250,f)){
        
        Key * keyTmp=str_to_key(buffer);
        if(keyTmp!=NULL)
            cell_en_tete(&listC,keyTmp);
       
    }
    fclose(f);
    return listC;
}
void delete_cell_key(CellKey* c){
    if (c) {
        free(c->data);  
        c=c->next;
    }
    
}


void delete_list_keys(CellKey** c){
    if(!(*c)){
        printf("pas liste de cle");
        return;
    }
    CellKey *tmp = *c;
    while(*c){
        *c = (*c)->next;
        delete_cell_key(tmp);
        tmp=*c;
    }
}

typedef struct cellProtected{
    Protected  *data;
    struct cellProtected* next;

}CellProtected;


CellProtected* create_cell_protected(Protected *pr){
    CellProtected* cell_pr=(CellProtected*)malloc(sizeof(CellProtected));
    cell_pr->data=pr;
    cell_pr->next=NULL;
    return cell_pr;
}

void cell_protected_en_tete(CellProtected **CP,Protected *data){
    CellProtected *c=create_cell_protected(data);
    c->next=*CP;
    (*CP)=c;
}

CellProtected *read_protected(char *nomF){
    FILE *f =fopen(nomF,"r");
    CellProtected *listP=(CellProtected*)malloc(sizeof(CellProtected));
    char buffer[250];
    printf("READING SIGNs FROM A FILE\n");

    while(fgets(buffer,250,f)){

        
        Protected *keyTmp=str_to_protected(buffer);
        cell_protected_en_tete(&listP,keyTmp);
    }
    fclose(f);
    return listP;
}


void print_list_protected(CellProtected *LCP){
    if(!LCP){
        printf("pas de liste");
        exit(1);
        return ;
    }
    printf("debut affichage d'une liste de protected\n");
    CellProtected *tmp=LCP;
    while(tmp){
        printf(" %s\n",protected_to_str(tmp->data));
        tmp=tmp->next;
    }
    printf("fin affichage d'une liste de protected\n");
}



void delete_cell_protected(CellProtected *CP){
   free(CP->data->pKey);
    free(CP->data->sgn->content);
    free(CP->data->sgn);
    
}


void delete_list_protected(CellProtected *LCP){
      if(!LCP){
        printf("pas liste de signature declaree");
        return;
    }
    
    while(LCP){
        CellProtected *tmp=LCP;
        delete_cell_protected(tmp);
        LCP=LCP->next;
    }
    free(LCP);
}
 
//////////exo 6


void delete_fausse_signature(CellProtected *LCP){
    while(verify(LCP->data)==0){
        CellProtected *tmpr=LCP;
        delete_cell_protected(tmpr);
        LCP=LCP->next->next;
    }
    
    CellProtected *tmp=LCP; 
    while(tmp->next){
        if(verify(tmp->next->data)==0){
             CellProtected *tmp2=tmp->next;

            tmp->next=tmp->next->next;
            delete_cell_protected(tmp2);

        }
        tmp=tmp->next;
    
    }
}

////////////////Exo 6/////////////////////////////////:
typedef struct hashcell{
    Key* key;
    int val;
}HashCell;

typedef struct hastable{
    HashCell **tab;
    int size;

}HashTable;


HashCell* create_hashcell(Key* key){
    HashCell *hc=(HashCell*)malloc(sizeof(HashCell));
    hc->key=key;
    hc->val=0;
    return hc;

}

int hash_function(Key *key,int size){
   /* double A=(sqrt(5)-1)/2;

    long a =key->value+key->n;
    
    double tmp=(a*A-(int)(a*A));
    
    return (int)(size*tmp);

*/
    return key->value%size;
}

int find_position(HashTable *t,Key* key){

    if(t->tab[hash_function(key,t->size)]==NULL){
        return hash_function(key,t->size);
    }

    if(t->tab[hash_function(key,t->size)]->key->value==key->value &&   t->tab[hash_function(key,t->size)]->key->n==key->n){
        return hash_function(key,t->size);
    }
    else{
        for(int i=0;i<t->size;i++){
            if(t->tab[i]!=NULL){
                if(t->tab[i]->key->n==key->n && t->tab[i]->key->value==key->value){
                return i;
            }
        }
        }


    }

    return hash_function(key,t->size);
      
}

HashTable *create_hashtable(CellKey* keys,int size){
   
    HashTable *new=(HashTable*)malloc(sizeof(HashTable));
    new->size=size;
    new->tab=(HashCell**)malloc(sizeof(HashCell*)*size);

    for(int i=0 ; i<size;i++){
        new->tab[i]=NULL;
    }
    CellKey* tmp=keys;
    while(tmp){
        new->tab[find_position(new,tmp->data)]=create_hashcell(tmp->data);
        
        tmp=tmp->next;

    }
    return new;
}
void delete_hastable(HashTable* t){
    
    if(!t){
        printf("pas de table de hachage\n\n");
    }

    for(int i=0;i<t->size;i++){
        if(t->tab[i]){
            free(t->tab[i]);
        }
    }
    free(t);


}

Key* compute_winner(CellProtected* decl, CellKey* candidates,CellKey* voters, int sizeC, int sizeV) {
  
  HashTable *HC=create_hashtable(candidates,sizeC);
  HashTable *HV=create_hashtable(voters,sizeV);
  
  
  while(decl){
      
     if( HV->tab[find_position(HV,decl->data->pKey)]->val==0) {
         if(strcmp(key_to_str(HC->tab[find_position(HC,decl->data->pKey)]->key),decl->data->mess)==0){
             if (strcmp(key_to_str(HC->tab[find_position(HC,decl->data->pKey)]->key),key_to_str(HV->tab[find_position(HV,decl->data->pKey)]->key))==0){
                
                 HV->tab[find_position(HV,decl->data->pKey)]->val=1;
                 HC->tab[find_position(HC,decl->data->pKey)]->val++;
             }
           
         }
        
     }
     decl=decl->next;

      

  }
  int win= HC->tab[0]->val;
  for(int i =0;i<HC->size;i++){
      if(win<HC->tab[i]->val){
          win=HC->tab[i]->val;
      }
  }
  return HC->tab[win]->key;


}
typedef struct block {
Key * author ;
CellProtected * votes ;
unsigned char * hash ;
unsigned char * previous_hash ;
int nonce ;
 } Block ;

void write_block(char *nomF,Block *block){

   FILE *f=fopen(nomF,"w");
   if (f==NULL){
       printf("Error");
       exit(1);
   }
  
    CellProtected *tmp=block->votes;
   fprintf(f,"%s,%hhn,%hhn,%d\n",key_to_str(block->author),block->hash,block->previous_hash,block->nonce);
   while(tmp){
       fprintf(f,"%s\n",protected_to_str(block->votes->data));
       tmp=tmp->next;
   }
   fclose(f);


}

Block* str_to_block(char *nomF){

    FILE *f=fopen(nomF,"r");
    if(f ==NULL){
        printf("Erreur");
        exit(1);
    }
    char key[250];
    char votes[250];
    unsigned char hash[100];
    unsigned char previous_hash[100];
    int nonce;

    char buffer[500];
    fgets(buffer,500,f);
    sscanf(buffer,"%s,%hhn,%hhn,%d\n",key,hash,previous_hash,&nonce);

    Block *block =(Block*)malloc(sizeof(Block));

      while(fgets(buffer,500,f)){
          sscanf(buffer,"%s\n",votes);
          cell_protected_en_tete(&(block->votes),str_to_protected(votes));
    }
    block->author=str_to_key(key);
    block->hash=hash;
    block->previous_hash=previous_hash;

    return block;
   

}

char* block_to_str(Block* block){

    char* str=(char*)malloc(sizeof(char)*10);
    char * key = key_to_str(block->author);
    char voters[250];
    Block *tmp=block;
    while(tmp->votes){
       sprintf(voters,"%s\n",protected_to_str(tmp->votes->data));
       tmp->votes=tmp->votes->next;
    }

    sprintf(str," %s\t%hhn\t%s\t%d\n ", key,block->previous_hash,voters,block->nonce);

    return str;

    
}


unsigned char *SHA(const char *s){
    unsigned char *d=SHA256((unsigned char *)s,strlen(s),0);

    for(int i=0;i<SHA256_DIGEST_LENGTH ; i ++)
        printf("%02x",d[i]);
    putchar('\n');
    return d;
    
}
int compte_zero(unsigned char *d ,int n){
     int cpt =0;
        for(int i =0;d[i]!='\0';i++){
            if(d[i]=='0'){
                cpt++;
            }

        }
        if(n==cpt){
            return 1;
        }
        return 0;
}

void  compute_proof_of_work(Block *B, int d){
    while(compte_zero(B->hash,d)==0){
        B->nonce++;
    }

}


int verify_block(Block *B,int d){
    if(B->nonce==4*d){
        return 1;
    }
    else{
        return 0;
    }
}

void delete_block(Block *b){  /// pas tester

    free(b->hash);
    free(b->previous_hash);
    CellProtected *tmp=b->votes;
    while(tmp){
        free(tmp);
       tmp=tmp->next;
    }

}
////////////////Exo 8
typedef struct block_tree_cell {
 Block * block ;
 struct block_tree_cell * father ;
 struct block_tree_cell * firstChild ;
 struct block_tree_cell * nextBro ;
 int height ;
}CellTree ;

CellTree* create_node(Block *b){
    CellTree *tree=(CellTree*)malloc(sizeof(CellTree));
    tree->block=b;
    tree->father=NULL;
    tree->firstChild=NULL;
    tree->nextBro=NULL;
    return tree;
}

int update_height(CellTree *father,CellTree*child) {
    int hauteur=father->height;

    father->height=fmax(father->height,child->height+1);
    if(hauteur!=father->height){
        return 1;
    }
    return 0;
   

}

void add_child(CellTree *father,CellTree* child ){
    
    if(father->firstChild==NULL){
        father->firstChild=child;
        child->father=father;
        update_height(father,child);
    }
   // CellTree *tree=father->firstChild;
    if(father->firstChild) {
       if(father->firstChild->nextBro==NULL){
           father->firstChild->nextBro=child;
       }
    }
    //fonction à termiber
}
void print_tree(CellTree *tree){


    if(tree){
        printf("Height: %d, hash_value: %hhn\n", tree->height, tree->block->hash);
    
        print_tree(tree->father);
        print_tree(tree->firstChild);
        print_tree(tree->nextBro);
    }
    return;
}

void delete_node(CellTree *node){
    if(node)
        delete_block(node->block);
    free(node);

}

void delete_tree(CellTree* tree){
    if(tree !=NULL){
    free(tree->block->author);
    delete_cell_protected(tree->block->votes);
    delete_block(tree->block);
    delete_node(tree->father);
    delete_tree(tree->firstChild);
    delete_tree(tree->nextBro);


    }
    free(tree);
}
CellTree* highest_child(CellTree* cell){
    CellTree *fils=cell->firstChild;
    while(cell->nextBro){
        if(fils->height<cell->nextBro->height){
            fils=cell->nextBro;
        }
        cell->nextBro=cell->nextBro->nextBro;
    }
    return fils;
}
CellTree* last_node(CellTree* tree){
    if(tree->firstChild==NULL)
        return highest_child(tree);
       
    return last_node( highest_child(tree));
    
    

    
}
CellProtected* fusion(CellProtected* first, CellProtected* second){

    // la complexite et theta du # des elements dans la premiere liste, 
    // pour avoir la complexite O(1), il faut utiliser une liste doublement chainee
    
    CellProtected  *element = first;
    if (element == NULL)
        return second;

    while(element->next){
      element = element->next;
      if(element->next==NULL)
        element->next=second;
    }
    return element;
}
CellProtected* fusion_long(CellTree* first, CellTree* second){
    CellTree *f=highest_child(first);
    CellTree *s=highest_child(second);
    return fusion(f->block->votes,s->block->votes);
}

void submit_vote(Protected *p){
    FILE *f=fopen("Pending votes.txt","a");
   if (f==NULL){
       printf("Error");
       exit(1);
   }
   fprintf(f,"%s\n",protected_to_str(p));
   fclose(f);
}

void create_block(CellTree *tree,Key *author,int d){
    CellProtected* votes=read_protected("Pending_votes.txt");

    Block* B=malloc(sizeof(Block));
    B->author=author;
    compute_proof_of_work(B,d);
    CellTree* hash= last_node(tree);
    B->hash=hash->block->hash;
    B->previous_hash=hash->block->previous_hash;
    B->votes=votes;
    remove("Pending_votes.txt");

    write_block("Pending_block",B);
    
    
}
void add_block(int d,char* name) {
    
    Block *b=str_to_block("Pending_votes.txt");
    if(verify_block(b,d)==1){
         write_block(name,b);
        opendir("./Blockchain/",name,_IOS_APPEND);//comment on faiiiittt
    }
     remove("Pending_votes.txt");
}
CellTree* read_tree(){

DIR * rep = opendir ("./Blockchain/") ;
 if ( rep != NULL ){
    struct dirent * dir ;
    while (( dir = readdir ( rep ))) {
        if ( strcmp(dir->d_name ,".")!=0 &&  strcmp(dir->d_name ,"..") !=0) {
            printf ("Chemin du fichier : ./ Blockchain/%s \n",dir->d_name);
        }
    }
 closedir ( rep ) ;
 }
 //finir urgeeent
}
Key *compute_winner_BT(CellTree* tree,CellKey* candidates,CellKey* voters, int sizeC, int sizeV) {



    CellProtected* liste1=fusion(tree->father->block->votes, tree->firstChild->block->votes);
    CellProtected* votes=fusion(liste1, tree->nextBro->block->votes);
    delete_fausse_signature(votes);

    return compute_winner(votes, candidates,voters, sizeC,sizeV);



}



int main(){
    Key * pKey = malloc ( sizeof ( Key ) ) ;
    Key * sKey = malloc ( sizeof ( Key ) ) ;
    init_pair_keys ( pKey , sKey ,3 ,7) ;
        printf ("pKey : %lx , %lx \n", pKey->value , pKey->n ) ;
        printf (" sKey : %lx , %lx \n", sKey->value , sKey->n ) ;
    printf("hash function de key= %d\n",hash_function(pKey,20));
    printf("hash function de key= %d\n",hash_function(sKey,20));

     CellKey *ck=create_cell_key(pKey);
        printf("affichage ck\n");
       cell_en_tete(&ck,sKey);

   create_hashtable(ck,20);
   







    return 0;
}
