# © 2026 NTT DATA Japan Co., Ltd. & NTT InfraNet All Rights Reserved.

"""
AIM_0010_registAuthorizationInformation.py

処理名:
    認可情報登録

概要:
    認可グループとそのグループが参照可能なレイヤの情報を認可レイヤ（設備）に登録する。
    既に参照可能なレイヤが登録されている場合は、既存データを削除した上で登録を行う。

    【補足】
    本バッチの実行にはchardetライブラリ（バージョン: 5.2.0）が必要です。
    chardetがインストールされていない場合、文字コード確認でエラーとなりますので、事前にインストールしてください。

実行コマンド形式:
    python3 [バッチ格納先パス]/AIM_0010_registAuthorizationInformation.py
    --filename=[ファイル名]
"""

import argparse
import csv
import os
import traceback
from datetime import datetime
from pathlib import Path

import chardet
from core.config_reader import read_config
from core.constants import Constants
from core.database import Database
from core.logger import LogManager
from core.secretProperties import SecretPropertiesSingleton
from core.validations import Validations
from util.checkProviderExistence import check_provider_existence_code_and_id

log_manager = LogManager()
logger = log_manager.get_logger("AIM_0010_認可情報登録")
config = read_config(logger)

# 設定ファイルから取得
AUTHORIZATION_CSV_WORK_FOLDER = config["folderPass"][
    "authorization_csv_work_folder"
].strip()
AUTHORIZATION_GROUP_NAME = config["constant"]["authorization_group_name"].strip()
LAYER_ID = config["constant"]["layer_id"].strip()
AREA_IGNORE_FLAG = config["constant"]["area_ignore_flag"].strip()
SECRET_NAME = config["aws"]["secret_name"].strip()


# 起動パラメータを受け取る関数
def parse_args():
    try:
        # 完全一致のみ許可
        parser = argparse.ArgumentParser(allow_abbrev=False, exit_on_error=False)
        parser.add_argument("--filename", required=False)
        return parser.parse_args()
    except Exception as e:
        # コマンドライン引数の解析に失敗した場合
        logger.error("BPE0037", str(e.message))
        logger.process_error_end()


# 1. 入力値チェック
def validate_file_name(file_name):
    # 必須パラメータチェック
    if not file_name:
        logger.error("BPE0018", "ファイル名")
        logger.process_error_end()

    # 接頭辞が"referenceable_layer_facility_"であること
    if not Validations.is_prefix(
        file_name, Constants.PREFIX_REFERENCEABLE_LAYER_FACILITY
    ):
        logger.error("BPE0019", "ファイル名", file_name)
        logger.process_error_end()

    # 拡張子が".csv"であること
    if not Validations.is_suffix(file_name, Constants.SUFFIX_CSV):
        logger.error("BPE0019", "ファイル名", file_name)
        logger.process_error_end()

    # 接頭辞"referenceable_layer_facility_"と拡張子".csv"を除去
    body = file_name[
        # fmt: off
        len(Constants.PREFIX_REFERENCEABLE_LAYER_FACILITY):-len(Constants.SUFFIX_CSV)
        # fmt: on
    ]

    # 接頭辞と拡張子を除去した値が"_"を含むこと
    if "_" not in body:
        logger.error("BPE0019", "ファイル名", file_name)
        logger.process_error_end()

    # [公益事業者・道路管理者コード]と[申請日付]を分離
    provider_code, application_date = body.rsplit("_", 1)

    # 半角数字とハイフンのみで構成されていること
    if not Validations.is_digit_hyphen(provider_code):
        logger.error("BPE0019", "ファイル名", file_name)
        logger.process_error_end()

    # 桁数（1以上20以下）
    if not Validations.is_valid_length(provider_code, 1, 20):
        logger.error("BPE0019", "ファイル名", file_name)
        logger.process_error_end()

    # フォーマットがYYYYMMDD形式であること
    # 存在する日付であること
    if not Validations.is_date_format(application_date):
        logger.error("BPE0019", "ファイル名", file_name)
        logger.process_error_end()

    # 入力値チェック完了後、公益事業者・道路管理者コードを返す
    return provider_code


# 2. CSVファイル存在確認
def check_csv_file_exists(file_path):
    # 対象のCSVファイルが存在するか
    if not file_path.is_file():
        logger.error("BPE0033", file_path)
        logger.process_error_end()


# 3. CSVファイル文字コード確認
def check_csv_encoding(file_path):
    # CSVファイルの文字コードがUTF-8であること
    try:
        with open(file_path, "rb") as f:
            rawdata = f.read()
            result = chardet.detect(rawdata)
            detected_encoding = result["encoding"]

        if not (detected_encoding.upper() == Constants.CHARACTER_ENCODING_UTF_8):
            logger.error("BPE0008", file_path)
            logger.process_error_end()
    except Exception:
        logger.error("BPE0007", file_path)
        logger.process_error_end()


# 4. CSVファイル読み込み（認可情報リスト作成）
def read_csv(file_path):
    # CSVファイルを読み込み認可情報リストを作成
    with open(
        file_path, mode="r", encoding=Constants.CHARACTER_ENCODING_UTF_8
    ) as csv_file:
        reader = csv.reader(csv_file)
        authorization_information_list = [row for row in reader]
        return authorization_information_list


# 5. ヘッダー項目チェック
def validate_header(header):
    # 全体の列数が3であること
    if not len(header) == 3:
        logger.error("BPE0062", "1", header)
        logger.process_error_end()

    # ヘッダーを展開
    (authorization_group_name, layer_id, area_ignore_flag) = header

    # ヘッダーの列名が設定ファイルの値と一致すること
    # 認可グループ名
    if not authorization_group_name == AUTHORIZATION_GROUP_NAME:
        logger.error("BPE0064", AUTHORIZATION_GROUP_NAME, "1", header)
        logger.process_error_end()
    # レイヤID
    if not layer_id == LAYER_ID:
        logger.error("BPE0064", LAYER_ID, "1", header)
        logger.process_error_end()
    # エリア無視フラグ
    if not area_ignore_flag == AREA_IGNORE_FLAG:
        logger.error("BPE0064", AREA_IGNORE_FLAG, "1", header)
        logger.process_error_end()


# 6. 認可情報リスト項目チェック
def validate_authorization_information_rows(authorization_information_list):

    # 認可グループ名リスト
    authorization_group_name_list = []
    # レイヤIDリスト
    layer_id_list = []

    # 公益事業者・道路管理者IDの比較チェックをするための基準値
    base_provider_id = None

    # ヘッダーを除いたレイヤ情報リストのチェック
    for row_count, authorization_information in enumerate(
        authorization_information_list[1:], start=2
    ):  # ヘッダーを除く

        # 全体の列数が3であること
        if not len(authorization_information) == 3:
            logger.error("BPE0062", row_count, authorization_information)
            logger.process_error_end()

        # テンプレートを展開
        (authorization_group_name, layer_id, area_ignore_flag) = (
            authorization_information
        )

        # 認可グループ名チェック
        # 必須チェック
        if not Validations.is_required_for_csv(authorization_group_name):
            logger.error(
                "BPE0063",
                AUTHORIZATION_GROUP_NAME,
                row_count,
                authorization_information,
            )
            logger.process_error_end()

        # 桁数（1以上20以下）
        if not Validations.is_valid_length(authorization_group_name, 1, 20):
            logger.error(
                "BPE0064",
                AUTHORIZATION_GROUP_NAME,
                row_count,
                authorization_information,
            )
            logger.process_error_end()

        # レイヤIDチェック
        # 必須チェック
        if not Validations.is_required_for_csv(layer_id):
            logger.error("BPE0063", LAYER_ID, row_count, authorization_information)
            logger.process_error_end()

        # 半角英数字とアンダースコアのみで構成されていること
        if not Validations.is_alnum_underscore(layer_id):
            logger.error("BPE0064", LAYER_ID, row_count, authorization_information)
            logger.process_error_end()

        # 桁数（1以上50以下）
        if not Validations.is_valid_length(layer_id, 1, 50):
            logger.error("BPE0064", LAYER_ID, row_count, authorization_information)
            logger.process_error_end()

        # レイヤIDから公益事業者・道路管理者IDを抽出
        provider_id = layer_id.split("_")[-1]

        # 末尾の公益事業者・道路管理者IDが同じ値であること
        if base_provider_id is None:
            base_provider_id = provider_id
        elif not provider_id == base_provider_id:
            # 末尾の事業者IDが同一であること
            logger.error("BPE0064", LAYER_ID, row_count, authorization_information)
            logger.process_error_end()

        # エリア無視フラグチェック
        # 必須チェック
        if not Validations.is_required_for_csv(area_ignore_flag):
            logger.error(
                "BPE0063", AREA_IGNORE_FLAG, row_count, authorization_information
            )
            logger.process_error_end()
        if (
            # 半角数字1文字で構成されていること
            not Validations.is_single_digit(area_ignore_flag)
            # 0または1であること
            or not Validations.is_value_in_list(
                int(area_ignore_flag), Constants.DIGIT_FLAG_LIST
            )
        ):
            logger.error(
                "BPE0064", AREA_IGNORE_FLAG, row_count, authorization_information
            )
            logger.process_error_end()

        # 認可グループ名リストに追加
        authorization_group_name_list.append(authorization_group_name)
        # レイヤIDリストに追加
        layer_id_list.append(layer_id)

    # 配列の重複を削除
    authorization_group_name_list = list(dict.fromkeys(authorization_group_name_list))
    layer_id_list = list(dict.fromkeys(layer_id_list))

    return base_provider_id, authorization_group_name_list, layer_id_list


# 8. 認可グループ存在確認
def check_authorization_group_exists(
    db_connection, db_mst_schema, authorization_group_name_list
):
    # 認可グループ名リスト中の認可グループ名が認可グループマスタに存在するか確認
    query = (
        "WITH v(authorization_group_name) AS (SELECT UNNEST(%s::text[])) "
        "SELECT ARRAY_AGG(v.authorization_group_name) FROM v "
        f"LEFT JOIN {db_mst_schema}.mst_authorization_group m "
        "ON v.authorization_group_name = m.authorization_group_name "
        "WHERE m.authorization_group_name IS NULL;"
    )
    result = Database.execute_query(
        db_connection,
        logger,
        query,
        (authorization_group_name_list,),
        fetchone=True,
    )
    if result:
        logger.error(
            "BPE0055",
            "認可グループマスタ",
            "認可グループ名",
            result,
        )
        logger.process_error_end()


# 9. 認可グループID取得
def get_authorization_group_codelist(
    db_connection, db_mst_schema, authorization_group_name_list
):
    # 認可グループマスタから認可グループ名・認可グループIDをJSONオブジェクト形式で取得
    query = (
        "SELECT json_object_agg(authorization_group_name, authorization_group_id) "
        f"FROM {db_mst_schema}.mst_authorization_group "
        "WHERE authorization_group_name IN %s;"
    )
    result = Database.execute_query(
        db_connection,
        logger,
        query,
        (tuple(authorization_group_name_list),),
        fetchone=True,
    )
    return result


# 10. 認可情報リスト修正
def modify_authorization_information_list(
    authorization_information_list, authorization_group_codelist
):
    # テンプレートIDリスト
    template_id_list = []

    # 10-1. ヘッダー削除（0番目の配列を削除）
    authorization_information_list_without_header = authorization_information_list[1:]

    # 修正後認可情報リスト
    modified_authorization_information_list = []

    for authorization_information in authorization_information_list_without_header:
        # 各項目を取得
        (
            authorization_group_name,
            layer_id,
            area_ignore_flag,
        ) = authorization_information

        # 10-2. 認可グループID置き換え
        authorization_group_id = authorization_group_codelist[authorization_group_name]

        # 10-3. テンプレートID追加
        template_id = "_".join(layer_id.split("_")[:-3])

        # 修正後の認可情報リストに追加
        # [認可グループID, レイヤID, エリア無視フラグ, テンプレートID]
        modified_authorization_information_list.append(
            [authorization_group_id, layer_id, int(area_ignore_flag), template_id]
        )

        # テンプレートIDリストに追加
        template_id_list.append(template_id)

    # 配列の重複を削除
    template_id_list = list(dict.fromkeys(template_id_list))

    return modified_authorization_information_list, template_id_list


# 11. テンプレート存在確認
def check_vector_layer_template_exists(db_connection, db_mst_schema, template_id_list):
    # ベクタレイヤテンプレートマスタに既存データが存在するか確認
    query = (
        f"SELECT (SELECT COUNT(DISTINCT template_id) "
        f"FROM {db_mst_schema}.mst_vector_layer_template "
        f"WHERE template_id IN %s) = %s;"
    )
    result = Database.execute_query(
        db_connection,
        logger,
        query,
        (tuple(template_id_list), len(template_id_list)),
        fetchone=True,
    )
    if not result:
        logger.error(
            "BPE0055",
            "ベクタレイヤテンプレートマスタ",
            "テンプレートID",
            template_id_list,
        )
        logger.process_error_end()


# 12. ベクタレイヤ存在確認
def check_vector_layer_exists(db_connection, db_mst_schema, layer_id_list):
    # レイヤIDリスト中のレイヤIDがベクタレイヤマスタに存在するか確認
    query = (
        "WITH v(layer_id) AS (SELECT UNNEST(%s::text[])) "
        "SELECT ARRAY_AGG(v.layer_id) FROM v "
        f"LEFT JOIN {db_mst_schema}.mst_vector_layer m "
        "ON v.layer_id = m.layer_id "
        "WHERE m.layer_id IS NULL;"
    )
    result = Database.execute_query(
        db_connection,
        logger,
        query,
        (layer_id_list,),
        fetchone=True,
    )
    if result:
        logger.error(
            "BPE0055",
            "ベクタレイヤマスタ",
            "レイヤID",
            result,
        )
        logger.process_error_end()


# 13. 認可レイヤ削除
def delete_referenceable_layer_facility(conn, db_mst_schema, provider_id):
    # 認可レイヤ（設備）から既存データを削除
    query = (
        f"DELETE FROM {db_mst_schema}.mst_referenceable_layer_facility "
        "WHERE provider_id = %s;"
    )
    Database.execute_query_no_commit(conn, logger, query, (provider_id,))


# 15. 認可レイヤ登録
def insert_referenceable_layer_facility(
    conn,
    db_mst_schema,
    authorization_information_list,
    provider_id,
    current_time,
):
    # 認可レイヤ（設備）に認可情報を登録
    query = (
        f"INSERT INTO {db_mst_schema}.mst_referenceable_layer_facility "
        "(authorization_group_id, layer_id, provider_id, "
        "area_ignore_flag, template_id, created_by, created_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)"
    )
    for authorization_information in authorization_information_list:
        # 各項目を取得
        (
            authorization_group_id,
            layer_id,
            area_ignore_flag,
            template_id,
        ) = authorization_information
        Database.execute_query_no_commit(
            conn,
            logger,
            query,
            (
                authorization_group_id,
                layer_id,
                provider_id,
                area_ignore_flag,
                template_id,
                "system",
                current_time,
            ),
        )


# 17. CSVファイル削除
def delete_csv_file(file_path):
    # 警告フラグ
    warning_flag = False

    # CSVファイルの削除
    try:
        os.remove(file_path)
    except Exception:
        # 削除に失敗した場合、警告ログを出力
        logger.warning("BPW0026", str(file_path))
        warning_flag = True
    return warning_flag


# 18. 終了コード返却
def determine_exit_code(warning_flag):
    # 警告フラグがTRUEの場合
    if warning_flag:
        # 警告終了
        logger.process_warning_end()
    # 警告フラグがFALSEの場合
    else:
        # 正常終了
        logger.process_normal_end()


# メイン処理
# 認可情報登録
def main():

    try:
        # 開始ログ出力
        logger.process_start()

        # 起動パラメータの取得
        file_name = parse_args().filename

        # 1. 入力値チェック
        provider_code = validate_file_name(file_name)

        # CSVファイルのパスを設定
        file_path = Path(AUTHORIZATION_CSV_WORK_FOLDER) / file_name

        # 2. CSVファイル存在確認
        check_csv_file_exists(file_path)

        # 3. CSVファイル文字コード確認
        check_csv_encoding(file_path)

        # 4. CSVファイル読み込み（認可情報リスト作成）
        authorization_information_list = read_csv(file_path)

        # 5. ヘッダー項目チェック
        validate_header(authorization_information_list[0])

        # 6. 認可情報リスト項目チェック
        (
            base_provider_id,
            authorization_group_name_list,
            layer_id_list,
        ) = validate_authorization_information_rows(authorization_information_list)

        # secret_propsにAWS Secrets Managerの値を格納
        secret_props = SecretPropertiesSingleton(SECRET_NAME, config, logger)

        # シークレットからマスタ管理スキーマ名を取得
        db_mst_schema = secret_props.get("db_mst_schema")

        # DB接続を取得
        db_connection = Database.get_mstdb_connection(logger)

        # 7. 公共事業者・道路管理者存在確認
        check_provider_existence_code_and_id(
            db_connection, db_mst_schema, provider_code, base_provider_id, logger
        )

        # 8. 認可グループ存在確認
        check_authorization_group_exists(
            db_connection, db_mst_schema, authorization_group_name_list
        )

        # 9. 認可グループID取得
        authorization_group_codelist = get_authorization_group_codelist(
            db_connection, db_mst_schema, authorization_group_name_list
        )

        # 10. 認可情報リスト修正
        (authorization_information_list, template_id_list) = (
            modify_authorization_information_list(
                authorization_information_list, authorization_group_codelist
            )
        )

        # 11. テンプレート存在確認
        check_vector_layer_template_exists(
            db_connection, db_mst_schema, template_id_list
        )

        # 12. ベクタレイヤ存在確認
        check_vector_layer_exists(db_connection, db_mst_schema, layer_id_list)

        # 13～15で一つのトランザクション
        with db_connection as conn:
            # 13. 認可レイヤ削除
            delete_referenceable_layer_facility(conn, db_mst_schema, base_provider_id)

            # 14. 現在日時取得
            current_time = datetime.now()

            # 15. 認可レイヤ登録
            insert_referenceable_layer_facility(
                conn,
                db_mst_schema,
                authorization_information_list,
                base_provider_id,
                current_time,
            )
            # 全ての削除・登録処理が成功した場合のみコミット
            conn.commit()

        # 16. 登録成功ログ出力
        logger.info("BPI0020", authorization_group_name_list)

        # 17. CSVファイル削除
        warning_flag = delete_csv_file(file_path)

        # 18. 終了コード返却
        determine_exit_code(warning_flag)

    except Exception:
        logger.error("BPE0009", traceback.format_exc())
        logger.process_error_end()


if __name__ == "__main__":
    main()
