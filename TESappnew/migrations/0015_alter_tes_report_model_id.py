# Generated by Django 4.1.5 on 2023-03-07 05:49

from django.db import migrations
import djongo.models.fields


class Migration(migrations.Migration):

    dependencies = [
        ('TESappnew', '0014_tes_report_model'),
    ]

    operations = [
        migrations.AlterField(
            model_name='tes_report_model',
            name='id',
            field=djongo.models.fields.ObjectIdField(auto_created=True, db_column='_id', primary_key=True, serialize=False, verbose_name='report_id'),
        ),
    ]
