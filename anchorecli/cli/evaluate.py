import sys
import json
import click

import anchorecli.clients.apiexternal
import anchorecli.cli.utils

config = {}


@click.group(name="evaluate", short_help="Policy evaluation operations")
@click.pass_obj
def evaluate(ctx_config):
    global config
    config = ctx_config

    try:
        anchorecli.cli.utils.check_access(config)
    except Exception as err:
        print(anchorecli.cli.utils.format_error_output(config, "evaluate", {}, err))
        sys.exit(2)


@evaluate.command(
    name="check", short_help="Check latest policy evaluation for an image"
)
@click.option(
    "--show-history", is_flag=True, help="Show all previous policy evaluations"
)
@click.option("--detail", is_flag=True, help="Show detailed policy evaluation report")
@click.option(
    "--tag", help="Specify which TAG is evaluated for a given image ID or Image Digest"
)
@click.option(
    "--policy",
    help="Specify which POLICY to use for evaluate (defaults currently active policy)",
)
@click.argument("input_image", nargs=1)
def check(input_image, show_history, detail, tag, policy):
    """
    INPUT_IMAGE: Input image can be in the following formats: Image Digest, ImageID or registry/repo:tag
    """
    ecode = 0

    try:
        itype, image, imageDigest = anchorecli.cli.utils.discover_inputimage(
            config, input_image
        )

        if imageDigest:
            thetag = input_image
            if tag:
                thetag = tag
            elif itype == "tag":
                thetag = image
            else:
                raise Exception(
                    "input image name is not a tag, and no --tag is specified"
                )

            ret = anchorecli.clients.apiexternal.check_eval(
                config,
                imageDigest=imageDigest,
                history=show_history,
                detail=detail,
                tag=thetag,
                policyId=policy,
            )
            ecode = anchorecli.cli.utils.get_ecode(ret)
            if ret["success"]:
                print(
                    anchorecli.cli.utils.format_output(
                        config,
                        "evaluate_check",
                        {"detail": detail, "history": show_history, "tag": thetag},
                        ret["payload"],
                    )
                )
                ecode = anchorecli.cli.utils.get_eval_ecode(
                    ret["payload"], anchorecli.cli.utils.unquote_plus(imageDigest)
                )
            else:
                raise Exception(json.dumps(ret["error"], indent=4))
        else:
            raise Exception("could not get image record from anchore")

    except Exception as err:
        print(
            anchorecli.cli.utils.format_error_output(config, "evaluate_check", {}, err)
        )
        if not ecode:
            ecode = 2

    anchorecli.cli.utils.doexit(ecode)
