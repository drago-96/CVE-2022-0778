#include <openssl/ec.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>


EC_GROUP *get_ec_group_my(void)
{
    char* ec_p = "697";
    char* ec_a = "1";
    char* ec_b = "694";
    char* g_x = "1";
    char* g_y = "132";
    char* ec_order = "663";
    char* ec_cofactor = "1";

    int ok = 0;

    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    BIGNUM *tmp_1 = NULL;
    BIGNUM *tmp_2 = NULL;
    BIGNUM *tmp_3 = NULL;

    BN_CTX *ctx;
    ctx = BN_CTX_new();
    tmp_1 = BN_CTX_get(ctx);
    tmp_2 = BN_CTX_get(ctx);
    tmp_3 = BN_CTX_get(ctx);

    // build curve
    if (!BN_dec2bn(&tmp_1, ec_p))
        goto err;
    if (!BN_dec2bn(&tmp_2, ec_a))
        goto err;
    if (!BN_dec2bn(&tmp_3, ec_b))
        goto err;
    if ((group = EC_GROUP_new_curve_GFp(tmp_1, tmp_2, tmp_3, NULL)) == NULL)
        goto err;

    printf("Built group!\n");

    // build generator
    point = EC_POINT_new(group);
    if (point == NULL)
        goto err;
    if (!BN_dec2bn(&tmp_1, g_x) || !BN_dec2bn(&tmp_2, g_y))
        goto err;
    if (!EC_POINT_set_affine_coordinates_GFp(group, point, tmp_1, tmp_2, ctx))
        goto err;

    printf("Built generator!\n");

    // set generator
    if (point == NULL)
        goto err;
    if (!BN_dec2bn(&tmp_2, ec_order))
        goto err;
    if (!BN_dec2bn(&tmp_3, ec_cofactor))
        goto err;
    if (!EC_GROUP_set_generator(group, point, tmp_2, tmp_3)) {
        printf("Didn't set_generator\n");
        goto err;
    }
ok = 1;
err:
    BN_free(tmp_1);
    BN_free(tmp_2);
    BN_free(tmp_3);
    EC_POINT_free(point);
    if (!ok) {
        EC_GROUP_free(group);
        return NULL;
    }
    return (group);
}

int main() {
    EC_GROUP *group;
    group = get_ec_group_my();
    if (group == NULL) {
        printf("No group built!\n");
        unsigned long err = ERR_get_error();
        char* err_str = ERR_error_string(err, NULL);
        printf("%ld %s\n", err, err_str);
    } else {
        printf("Group built!\n");
    }

    // set explicit encoding for the curve
    EC_GROUP_set_asn1_flag(group, OPENSSL_EC_EXPLICIT_CURVE);

    // set compressed form for point encoding
    EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_COMPRESSED);

    // write curve to file
    FILE *f;
    f = fopen("my_bad_group.der", "wb");
    int res = i2d_ECPKParameters_fp(f, group);
    fflush(f);
    fclose(f);
    printf("Result: %d\n", res);
}
